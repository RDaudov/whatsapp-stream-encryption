<?php

namespace Rdaudov\WhatsappEncryptor;

final class SidecarGenerator
{
    public const CHUNK_SIZE = 65536;
    public const OVERLAP_SIZE = 16;

    public static function generate(string $dataSource, string $macKey): string
    {
        $sidecar = '';
        $dataLength = strlen($dataSource);
        $chunkSize = self::CHUNK_SIZE;
        $overlap = self::OVERLAP_SIZE;
        $fullChunkLen = $chunkSize + $overlap;

        for ($n = 0; $n * $chunkSize < $dataLength; $n++) {
            $start = $n * $chunkSize;
            $chunkToHash = substr($dataSource, $start, $fullChunkLen);
            if ($chunkToHash === '') {
                break;
            }
            $mac = hash_hmac('sha256', $chunkToHash, $macKey, true);
            $sidecar .= substr($mac, 0, 10);
        }
        return $sidecar;
    }
}