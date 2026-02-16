<?php

namespace Rdaudov\WhatsappEncryptor\Tests;

use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Rdaudov\WhatsappEncryptor\DecryptingStream;
use Rdaudov\WhatsappEncryptor\Tests\DTO\MediaFixtureDTO;

class DecryptingStreamTest extends TestCase
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

    #[DataProvider('fixtureProvider')]
    public function testDecryptsCorrectlyWithFixtures(MediaFixtureDTO $fixture): void
    {
        $encryptedStream = Utils::streamFor($fixture->expectedEncryptedContent);
        $decryptingStream = new DecryptingStream($encryptedStream, $fixture->mediaKey, $fixture->mediaType);
        $decryptedContent = $decryptingStream->getContents();
        $decryptingStream->close();

        $this->assertSame(
            $fixture->originalContent,
            $decryptedContent,
            "Decrypted content for {$fixture->mediaType} does not match original."
        );
    }

    #[DataProvider('fixtureProvider')]
    public function testDecryptFailsWithWrongKey(MediaFixtureDTO $fixture): void
    {
        $wrongKey = str_repeat('x', 32);
        $encryptedStream = Utils::streamFor($fixture->expectedEncryptedContent);
        $decryptingStream = new DecryptingStream($encryptedStream, $wrongKey, $fixture->mediaType);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('MAC validation failed');
        $decryptingStream->getContents();
    }

    #[DataProvider('fixtureProvider')]
    public function testDecryptFailsWithCorruptedData(MediaFixtureDTO $fixture): void
    {
        $corrupted = $fixture->expectedEncryptedContent;
        $corrupted[0] = ~$corrupted[0];
        $encryptedStream = Utils::streamFor($corrupted);
        $decryptingStream = new DecryptingStream($encryptedStream, $fixture->mediaKey, $fixture->mediaType);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('MAC validation failed');
        $decryptingStream->getContents();
    }

    #[DataProvider('fixtureProvider')]
    public function testDecryptFailsWithTruncatedData(MediaFixtureDTO $fixture): void
    {
        $truncated = substr($fixture->expectedEncryptedContent, 0, 5);
        $encryptedStream = Utils::streamFor($truncated);
        $decryptingStream = new DecryptingStream($encryptedStream, $fixture->mediaKey, $fixture->mediaType);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid encrypted payload: too short');
        $decryptingStream->getContents();
    }

    public function testDecryptStreamCanBeReadInChunks(): void
    {
        $fixture = new MediaFixtureDTO('VIDEO');
        $encryptedStream = Utils::streamFor($fixture->expectedEncryptedContent);
        $decryptingStream = new DecryptingStream($encryptedStream, $fixture->mediaKey, 'VIDEO');

        $decrypted = '';
        while (!$decryptingStream->eof()) {
            $decrypted .= $decryptingStream->read(8192);
        }
        $decryptingStream->close();

        $this->assertSame($fixture->originalContent, $decrypted);
    }

    public function testDecryptStreamIsNotWritable(): void
    {
        $fixture = new MediaFixtureDTO('IMAGE');
        $encryptedStream = Utils::streamFor($fixture->expectedEncryptedContent);
        $decryptingStream = new DecryptingStream($encryptedStream, $fixture->mediaKey, 'IMAGE');

        $this->assertFalse($decryptingStream->isWritable());

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Cannot write to a decrypting stream');
        $decryptingStream->write('test');
    }
}