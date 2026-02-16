<?php

namespace Rdaudov\WhatsappEncryptor;

use Psr\Http\Message\StreamInterface;
use Rdaudov\WhatsappEncryptor\Traits\TKeyDerivation;
use RuntimeException;
use Throwable;

final class EncryptingStream implements StreamInterface
{
    use TKeyDerivation;

    private const TEMP_STREAM_MAX_MEMORY = 2 * 1024 * 1024;

    private readonly StreamInterface $decoratedStream;
    private $sourceStream;
    private readonly string $iv;
    private readonly string $cipherKey;
    private readonly string $macKey;
    private bool $finalized = false;
    private bool $isStreamable = false;
    private string $sidecar = '';

    public function __construct(StreamInterface $decoratedStream, string $mediaKey, string $mediaType)
    {
        $this->decoratedStream = $decoratedStream;
        $this->isStreamable = in_array($mediaType, ['VIDEO', 'AUDIO'], true);

        $this->sourceStream = fopen('php://temp/maxmemory:' . self::TEMP_STREAM_MAX_MEMORY, 'r+');
        if ($this->sourceStream === false) {
            throw new RuntimeException('Failed to open temporary stream for buffering.');
        }

        $keys = $this->deriveKeys($mediaKey, $mediaType);
        $this->iv = $keys['iv'];
        $this->cipherKey = $keys['cipherKey'];
        $this->macKey = $keys['macKey'];
    }

    public function __destruct()
    {
        $this->close();
    }

    public function __toString(): string
    {
        try {
            $this->finalizeEncryption();
            return $this->decoratedStream->__toString();
        } catch (Throwable) {
            return '';
        }
    }

    public function close(): void
    {
        if (!$this->finalized) {
            $this->finalizeEncryption();
        }
        if (is_resource($this->sourceStream)) {
            fclose($this->sourceStream);
            $this->sourceStream = null;
        }
    }

    private function finalizeEncryption(): void
    {
        if ($this->finalized) {
            return;
        }

        rewind($this->sourceStream);
        $unencryptedData = stream_get_contents($this->sourceStream);
        if ($unencryptedData === false) {
            throw new RuntimeException('Failed to read unencrypted data from temporary stream.');
        }

        $encryptedData = openssl_encrypt(
            $unencryptedData,
            'aes-256-cbc',
            $this->cipherKey,
            OPENSSL_RAW_DATA,
            $this->iv
        );

        if ($encryptedData === false) {
            throw new RuntimeException('OpenSSL encryption failed: ' . openssl_error_string());
        }

        $dataToSign = $this->iv . $encryptedData;
        $mac = hash_hmac('sha256', $dataToSign, $this->macKey, true);
        $truncatedMac = substr($mac, 0, 10);
        $finalPayload = $encryptedData . $truncatedMac;

        if ($this->isStreamable) {
            $this->sidecar = SidecarGenerator::generate($this->iv . $encryptedData . $truncatedMac, $this->macKey);
        }

        $this->decoratedStream->rewind();
        $this->decoratedStream->write($finalPayload);
        $this->decoratedStream->rewind();

        $this->finalized = true;
    }

    public function getSidecar(): ?string
    {
        if (!$this->isStreamable) {
            return null;
        }
        $this->finalizeEncryption();
        return $this->sidecar;
    }

    public function detach()
    {
        $this->finalizeEncryption();
        if (is_resource($this->sourceStream)) {
            fclose($this->sourceStream);
            $this->sourceStream = null;
        }
        return $this->decoratedStream->detach();
    }

    public function getSize(): ?int
    {
        $this->assertFinalized(__FUNCTION__);
        return $this->decoratedStream->getSize();
    }

    public function tell(): int
    {
        $this->assertFinalized(__FUNCTION__);
        return $this->decoratedStream->tell();
    }

    public function eof(): bool
    {
        $this->assertFinalized(__FUNCTION__);
        return $this->decoratedStream->eof();
    }

    public function isSeekable(): bool
    {
        $this->assertFinalized(__FUNCTION__);
        return $this->decoratedStream->isSeekable();
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        $this->assertFinalized(__FUNCTION__);
        $this->decoratedStream->seek($offset, $whence);
    }

    public function rewind(): void
    {
        $this->assertFinalized(__FUNCTION__);
        $this->decoratedStream->rewind();
    }

    public function isWritable(): bool
    {
        return !$this->finalized;
    }

    public function write(string $string): int
    {
        if ($this->finalized) {
            throw new RuntimeException('Cannot write to a finalized stream.');
        }

        $bytesToWrite = strlen($string);
        $bytesWritten = 0;

        while ($bytesWritten < $bytesToWrite) {
            $result = fwrite($this->sourceStream, substr($string, $bytesWritten));
            if ($result === false) {
                throw new RuntimeException('Failed to write to temporary stream.');
            }
            $bytesWritten += $result;
        }
        return $bytesWritten;
    }

    public function isReadable(): bool
    {
        $this->assertFinalized(__FUNCTION__);
        return $this->decoratedStream->isReadable();
    }

    public function read(int $length): string
    {
        $this->assertFinalized(__FUNCTION__);
        return $this->decoratedStream->read($length);
    }

    public function getContents(): string
    {
        $this->assertFinalized(__FUNCTION__);
        $this->decoratedStream->rewind();
        return $this->decoratedStream->getContents();
    }

    public function getMetadata(?string $key = null)
    {
        return $this->decoratedStream->getMetadata($key);
    }

    private function assertFinalized(string $operation): void
    {
        if (!$this->finalized) {
            throw new RuntimeException(
                "Cannot call {$operation} on an unfinalized stream. Write all data and then call close() or getContents() first."
            );
        }
    }
}