<?php

namespace Rdaudov\WhatsappEncryptor\Tests;

use PHPUnit\Framework\TestCase;
use Rdaudov\WhatsappEncryptor\SidecarGenerator;

class SidecarGeneratorTest extends TestCase
{
    public function testGenerateReturnsEmptyForEmptyInput(): void
    {
        $macKey = str_repeat('a', 32);
        $result = SidecarGenerator::generate('', $macKey);
        $this->assertSame('', $result);
    }

    public function testGenerateCreatesCorrectNumberOfChunks(): void
    {
        $macKey = str_repeat('b', 32);
        $data = str_repeat('x', 70000); 
        $sidecar = SidecarGenerator::generate($data, $macKey);
        $this->assertSame(20, strlen($sidecar));
    }

    public function testGenerateChunkHmacMatchesExpected(): void
    {
        $macKey = str_repeat('c', 32);
        $data = 'Hello, World!';
        $expectedHmac = hash_hmac('sha256', $data, $macKey, true);
        $expectedTruncated = substr($expectedHmac, 0, 10);
        $sidecar = SidecarGenerator::generate($data, $macKey);
        $this->assertSame($expectedTruncated, $sidecar);
    }

    public function testGenerateForMultipleChunksValidatesEachChunk(): void
    {
        $macKey = str_repeat('e', 32);
        $chunkSize = SidecarGenerator::CHUNK_SIZE;
        $overlap = SidecarGenerator::OVERLAP_SIZE;
        $fullChunkLen = $chunkSize + $overlap;

        $data = str_repeat('a', $chunkSize * 3 + 100);

        $sidecar = SidecarGenerator::generate($data, $macKey);

        $dataLength = strlen($data);
        for ($n = 0; $n * $chunkSize < $dataLength; $n++) {
            $start = $n * $chunkSize;
            $chunk = substr($data, $start, $fullChunkLen);
            if ($chunk === '') {
                break;
            }
            $expectedChunkMac = substr(hash_hmac('sha256', $chunk, $macKey, true), 0, 10);
            $actualChunkMac = substr($sidecar, $n * 10, 10);
            $this->assertSame($expectedChunkMac, $actualChunkMac, "Chunk $n mismatch");
        }
    }
}