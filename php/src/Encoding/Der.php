<?php

declare(strict_types=1);

namespace HostFog\Sigil\Encoding;

use UnexpectedValueException;

/**
 * Just enough ASN.1 DER to build key structures and read ECDSA signatures.
 *
 * @internal
 */
final class Der
{
    private const INTEGER = 0x02;
    private const BIT_STRING = 0x03;
    private const OCTET_STRING = 0x04;
    private const NULL = 0x05;
    private const OID = 0x06;
    private const SEQUENCE = 0x30;

    public static function sequence(string ...$elements): string
    {
        return self::tlv(self::SEQUENCE, implode('', $elements));
    }

    /**
     * Encodes an unsigned big-endian integer.
     */
    public static function integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\0");
        if ($bytes === '' || ord($bytes[0]) > 0x7f) {
            $bytes = "\0" . $bytes;
        }

        return self::tlv(self::INTEGER, $bytes);
    }

    public static function bitString(string $bytes): string
    {
        return self::tlv(self::BIT_STRING, "\0" . $bytes);
    }

    public static function octetString(string $bytes): string
    {
        return self::tlv(self::OCTET_STRING, $bytes);
    }

    public static function null(): string
    {
        return self::tlv(self::NULL, '');
    }

    public static function oid(string $dotted): string
    {
        $arcs = array_map('intval', explode('.', $dotted));
        $body = chr(40 * $arcs[0] + $arcs[1]);

        foreach (array_slice($arcs, 2) as $arc) {
            $chunk = chr($arc & 0x7f);
            while ($arc >>= 7) {
                $chunk = chr(0x80 | ($arc & 0x7f)) . $chunk;
            }
            $body .= $chunk;
        }

        return self::tlv(self::OID, $body);
    }

    public static function explicit(int $tag, string $content): string
    {
        return self::tlv(0xa0 | $tag, $content);
    }

    /**
     * Reads a SEQUENCE of INTEGERs and returns their unsigned big-endian values.
     *
     * @return list<string>
     */
    public static function readIntegerSequence(string $der): array
    {
        $offset = 0;
        $body = self::read($der, $offset, self::SEQUENCE);
        if ($offset !== strlen($der)) {
            throw new UnexpectedValueException('Trailing data after DER sequence.');
        }

        $integers = [];
        $offset = 0;
        while ($offset < strlen($body)) {
            $integers[] = ltrim(self::read($body, $offset, self::INTEGER), "\0");
        }

        return $integers;
    }

    private static function tlv(int $tag, string $content): string
    {
        $length = strlen($content);
        if ($length < 0x80) {
            return chr($tag) . chr($length) . $content;
        }

        $lengthBytes = ltrim(pack('N', $length), "\0");

        return chr($tag) . chr(0x80 | strlen($lengthBytes)) . $lengthBytes . $content;
    }

    private static function read(string $der, int &$offset, int $expectedTag): string
    {
        if (strlen($der) < $offset + 2 || ord($der[$offset]) !== $expectedTag) {
            throw new UnexpectedValueException('Unexpected DER element.');
        }

        $length = ord($der[$offset + 1]);
        $offset += 2;

        if ($length > 0x80 && $length <= 0x82) {
            $lengthBytes = substr($der, $offset, $length & 0x7f);
            $offset += strlen($lengthBytes);
            $length = (int) hexdec(bin2hex($lengthBytes));
        } elseif ($length >= 0x80) {
            throw new UnexpectedValueException('Unsupported DER length.');
        }

        if (strlen($der) < $offset + $length) {
            throw new UnexpectedValueException('Truncated DER element.');
        }

        $content = substr($der, $offset, $length);
        $offset += $length;

        return $content;
    }
}
