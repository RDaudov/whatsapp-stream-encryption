<?php

namespace Rdaudov\WhatsappEncryptor;

use Psr\Http\Message\StreamInterface;
use Rdaudov\WhatsappEncryptor\Traits\TKeyDerivation;
use RuntimeException;
use Throwable;

final class DecryptingStream implements StreamInterface
{
    use TKeyDerivation;

    private const TEMP_STREAM_MAX_MEMORY = 2 * 1024 * 1024;

    private readonly StreamInterface $sourceStream;
    private $decryptedStream;

    private readonly string $iv;
    private readonly string $cipherKey;
    private readonly string $macKey;
    private bool $finalized = false;

    public function __construct(StreamInterface $sourceStream, string $mediaKey, string $mediaType)
    {
        $this->sourceStream = $sourceStream;
        $this->decryptedStream = fopen('php://temp/maxmemory:' . self::TEMP_STREAM_MAX_MEMORY, 'r+');

        if ($this->decryptedStream === false) {
            throw new RuntimeException('Failed to open temporary stream for decrypted content.');
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

    private function finalizeDecryption(): void
    {
        if ($this->finalized) {
            return;
        }

        $this->sourceStream->rewind();
        $encryptedPayload = $this->sourceStream->getContents();

        if (strlen($encryptedPayload) < 10) {
            throw new RuntimeException('Invalid encrypted payload: too short.');
        }

        $encryptedData = substr($encryptedPayload, 0, -10);
        $receivedMac = substr($encryptedPayload, -10);

        $dataToSign = $this->iv . $encryptedData;
        $calculatedMac = hash_hmac('sha256', $dataToSign, $this->macKey, true);
        $truncatedMac = substr($calculatedMac, 0, 10);

        if (!hash_equals($truncatedMac, $receivedMac)) {
            throw new RuntimeException('MAC validation failed. The data is corrupt or has been tampered with.');
        }

        $decryptedData = openssl_decrypt(
            $encryptedData,
            'aes-256-cbc',
            $this->cipherKey,
            OPENSSL_RAW_DATA,
            $this->iv
        );

        if ($decryptedData === false) {
            throw new RuntimeException('OpenSSL decryption failed: ' . openssl_error_string());
        }

        fwrite($this->decryptedStream, $decryptedData);
        rewind($this->decryptedStream);

        $this->finalized = true;
    }

    public function __toString(): string
    {
        try {
            return $this->getContents();
        } catch (Throwable) {
            return '';
        }
    }

    public function close(): void
    {
        if (is_resource($this->decryptedStream)) {
            fclose($this->decryptedStream);
            $this->decryptedStream = null;
        }
    }

    public function detach()
    {
        $this->close();
        return null;
    }

    public function getSize(): ?int
    {
        if (!$this->finalized) {
            $this->finalizeDecryption();
        }
        fseek($this->decryptedStream, 0, SEEK_END);
        return ftell($this->decryptedStream);
    }

    public function tell(): int
    {
        if (!$this->finalized) {
            $this->finalizeDecryption();
        }
        return ftell($this->decryptedStream);
    }

    public function eof(): bool
    {
        if (!$this->finalized) {
            $this->finalizeDecryption();
        }
        return feof($this->decryptedStream);
    }

    public function isSeekable(): bool
    {
        return true;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        if (!$this->finalized) {
            $this->finalizeDecryption();
        }
        fseek($this->decryptedStream, $offset, $whence);
    }

    public function rewind(): void
    {
        $this->seek(0);
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write(string $string): int
    {
        throw new RuntimeException('Cannot write to a decrypting stream.');
    }

    public function isReadable(): bool
    {
        return true;
    }

    public function read(int $length): string
    {
        if (!$this->finalized) {
            $this->finalizeDecryption();
        }
        return fread($this->decryptedStream, $length);
    }

    public function getContents(): string
    {
        if (!$this->finalized) {
            $this->finalizeDecryption();
        }
        rewind($this->decryptedStream);
        return stream_get_contents($this->decryptedStream);
    }

    public function getMetadata(?string $key = null)
    {
        if (!$this->finalized) {
            $this->finalizeDecryption();
        }
        $metadata = stream_get_meta_data($this->decryptedStream);
        return $key ? ($metadata[$key] ?? null) : $metadata;
    }
}
