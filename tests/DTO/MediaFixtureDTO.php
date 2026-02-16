<?php

namespace Rdaudov\WhatsappEncryptor\Tests\DTO;

/**
 * DTO to hold a complete set of test fixture data.
 */
class MediaFixtureDTO
{
    public string $mediaType;
    public string $originalContent;
    public string $mediaKey;
    public string $expectedEncryptedContent;

    public function __construct(string $mediaType)
    {
        $this->mediaType = $mediaType;
        $basePath = __DIR__ . '/../fixtures/';
        $this->originalContent = file_get_contents($basePath . $mediaType . '.original');
        $this->mediaKey = file_get_contents($basePath . $mediaType . '.key');
        $this->expectedEncryptedContent = file_get_contents($basePath . $mediaType . '.encrypted');
    }
}