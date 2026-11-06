<?php

declare(strict_types=1);

use HostFog\Sigil\Exception\SigilException;
use HostFog\Sigil\KeySet;
use HostFog\Sigil\Sigil;

require dirname(__DIR__) . '/vendor/autoload.php';

const TESTDATA = __DIR__ . '/../../testdata';
const NOW = 1800000000;

function readJson(string $path): array
{
    return json_decode(file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
}

function normalize(mixed $value): mixed
{
    if (!is_array($value)) {
        return $value;
    }
    if (!array_is_list($value)) {
        ksort($value);
    }

    return array_map(normalize(...), $value);
}

function generate(string $out): int
{
    $keys = KeySet::fromJson(readJson(TESTDATA . '/keys.json'));
    $interop = readJson(TESTDATA . '/interop.json');

    $entries = [];
    foreach ($interop['cases'] as $case) {
        $key = $keys->get($case['key']);
        $case['token'] = $case['kind'] === 'jws'
            ? Sigil::sign($interop['claims'], $key, ['alg' => $case['alg']])
            : Sigil::encrypt($interop['claims'], $key, ['alg' => $case['alg'], 'enc' => $case['enc']]);
        $entries[] = $case;
    }

    $flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;
    file_put_contents($out, json_encode($entries, $flags) . "\n");
    printf("wrote %d tokens to %s\n", count($entries), $out);

    return 0;
}

function check(string $in): int
{
    $keys = KeySet::fromJson(readJson(TESTDATA . '/keys.json'));
    $expected = normalize(readJson(TESTDATA . '/interop.json')['claims']);

    $failures = 0;
    $entries = readJson($in);
    foreach ($entries as $entry) {
        $label = trim(sprintf('%s %s %s %s', $entry['kind'], $entry['alg'], $entry['enc'] ?? '', $entry['key']));
        $options = ['algorithms' => [$entry['alg']], 'now' => NOW, 'issuer' => 'sigil', 'audience' => 'all'];

        try {
            $key = $keys->get($entry['key']) ?? throw new RuntimeException('unknown key');
            $token = $entry['kind'] === 'jws'
                ? Sigil::verify($entry['token'], $key, $options)
                : Sigil::decrypt($entry['token'], $key, $options);

            if ($entry['kind'] === 'jwe' && ($token->header['enc'] ?? null) !== $entry['enc']) {
                throw new RuntimeException('enc mismatch');
            }
            if (normalize($token->claims) !== $expected) {
                throw new RuntimeException('claims mismatch');
            }
            echo "ok   $label\n";
        } catch (SigilException | RuntimeException $e) {
            $failures++;
            echo "FAIL $label: {$e->getMessage()}\n";
        }
    }

    printf("%d/%d passed\n", count($entries) - $failures, count($entries));

    return $failures === 0 ? 0 : 1;
}

[, $command, $path] = $argv + [null, null, null];

exit(match (true) {
    $command === 'gen' && $path !== null => generate($path),
    $command === 'check' && $path !== null => check($path),
    default => (function (): int {
        fwrite(STDERR, "usage: php bin/interop.php gen <out.json> | check <in.json>\n");

        return 2;
    })(),
});
