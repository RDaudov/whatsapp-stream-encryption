<?php

namespace Rdaudov\WhatsappEncryptor\Tests;

use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Rdaudov\WhatsappEncryptor\DecryptingStream;
use Rdaudov\WhatsappEncryptor\EncryptingStream;
use Rdaudov\WhatsappEncryptor\Tests\DTO\MediaFixtureDTO;

class EncryptingStreamTest extends TestCase
{
    private const SUPPORTED_MEDIA_TYPES = ['IMAGE', 'VIDEO', 'AUDIO', 'DOCUMENT'];

    public static function fixtureProvider(): array
    {
        $result = [];
        foreach (self::SUPPORTED_MEDIA_TYPES as $type) {
            $result[$type] = [new MediaFixtureDTO($type)];
        }
        return $result;
    }

    public static function mediaTypeProvider(): array
    {
        $result = [];
        foreach (self::SUPPORTED_MEDIA_TYPES as $type) {
            $result[$type] = [$type];
        }
        return $result;
    }

    #[DataProvider('fixtureProvider')]
    public function testEncryptsCorrectlyWithFixtures(MediaFixtureDTO $fixture): void
    {
        $destinationStream = Utils::streamFor();
        $encryptingStream = new EncryptingStream(
            $destinationStream,
            $fixture->mediaKey,
            $fixture->mediaType
        );

        $encryptingStream->write($fixture->originalContent);
        $encryptingStream->close();
        $destinationStream->rewind();
        $actualEncryptedContent = $destinationStream->getContents();

        $this->assertSame(
            strlen($fixture->expectedEncryptedContent),
            strlen($actualEncryptedContent),
            "Encrypted content size for {$fixture->mediaType} does not match expected size."
        );
        $this->assertSame(
            $fixture->expectedEncryptedContent,
            $actualEncryptedContent,
            "Encrypted content for {$fixture->mediaType} does not match expected content."
        );
    }

    public static function streamableFixtureProvider(): array
    {
        $result = [];
        foreach (['VIDEO', 'AUDIO'] as $type) {
            $result[$type] = [new MediaFixtureDTO($type)];
        }
        return $result;
    }

    #[DataProvider('streamableFixtureProvider')]
    public function testGeneratesSidecarCorrectly(MediaFixtureDTO $fixture): void
    {
        $destinationStream = Utils::streamFor();
        $encryptingStream = new EncryptingStream(
            $destinationStream,
            $fixture->mediaKey,
            $fixture->mediaType
        );

        $encryptingStream->write($fixture->originalContent);
        $actualSidecar = $encryptingStream->getSidecar();
        $encryptingStream->close();

        $this->assertNotNull($actualSidecar, "Sidecar for {$fixture->mediaType} should not be null.");

        $sidecarPath = __DIR__ . '/fixtures/' . $fixture->mediaType . '.sidecar';
        if (file_exists($sidecarPath)) {
            $expectedSidecar = file_get_contents($sidecarPath);
            $this->assertSame(
                $expectedSidecar,
                $actualSidecar,
                "Sidecar for {$fixture->mediaType} does not match expected fixture."
            );
        }
    }

    public static function nonStreamableFixtureProvider(): array
    {
        $result = [];
        foreach (['IMAGE', 'DOCUMENT'] as $type) {
            $result[$type] = [new MediaFixtureDTO($type)];
        }
        return $result;
    }

    #[DataProvider('nonStreamableFixtureProvider')]
    public function testSidecarNullForNonStreamableTypes(MediaFixtureDTO $fixture): void
    {
        $destinationStream = Utils::streamFor();
        $encryptingStream = new EncryptingStream(
            $destinationStream,
            $fixture->mediaKey,
            $fixture->mediaType
        );
        $encryptingStream->write($fixture->originalContent);
        $this->assertNull($encryptingStream->getSidecar());
        $encryptingStream->close();
    }

    #[DataProvider('mediaTypeProvider')]
    public function testEncryptDecryptRoundTrip(string $mediaType): void
    {
        $originalContent = random_bytes(1024 * 512);
        $mediaKey = random_bytes(32);

        $encryptedStream = Utils::streamFor();
        $encryptingStream = new EncryptingStream($encryptedStream, $mediaKey, $mediaType);
        $encryptingStream->write($originalContent);
        $encryptingStream->close();

        $encryptedStream->rewind();
        $decryptingStream = new DecryptingStream($encryptedStream, $mediaKey, $mediaType);
        $decryptedContent = $decryptingStream->getContents();
        $decryptingStream->close();

        $this->assertSame($originalContent, $decryptedContent);
    }
}