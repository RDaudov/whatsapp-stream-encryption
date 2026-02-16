<?php

namespace Rdaudov\WhatsappEncryptor\Traits;

use InvalidArgumentException;
use RuntimeException;

trait TKeyDerivation
{
    private function deriveKeys(string $mediaKey, string $mediaType): array
    {
        $applicationInfoMap = [
            'IMAGE' => 'WhatsApp Image Keys',
            'VIDEO' => 'WhatsApp Video Keys',
            'AUDIO' => 'WhatsApp Audio Keys',
            'DOCUMENT' => 'WhatsApp Document Keys',
        ];

        if (!isset($applicationInfoMap[$mediaType])) {
            throw new InvalidArgumentException("Unsupported media type: {$mediaType}");
        }

        $applicationInfo = $applicationInfoMap[$mediaType];

        $mediaKeyExpanded = hash_hkdf(
            'sha256',
            $mediaKey,
            112,
            $applicationInfo
        );

        if ($mediaKeyExpanded === false) {
            throw new RuntimeException('Failed to derive keys using HKDF.');
        }

        $iv = substr($mediaKeyExpanded, 0, 16);
        $cipherKey = substr($mediaKeyExpanded, 16, 32);
        $macKey = substr($mediaKeyExpanded, 48, 32);
        $refKey = substr($mediaKeyExpanded, 80, 32);

        return [
            'iv' => $iv,
            'cipherKey' => $cipherKey,
            'macKey' => $macKey,
            'refKey' => $refKey,
        ];
    }
}
