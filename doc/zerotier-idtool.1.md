zerotier-idtool(1) -- tool for creating and manipulating ZeroTier identities
============================================================================

## SYNOPSIS

`zerotier-idtool` <command> [args]

## DESCRIPTION

**zerotier-idtool** is a command line utility for doing things with ZeroTier identities. A ZeroTier identity consists of a public/private key pair (or just the public if it's only an identity.public) and a 10-digit hexadecimal ZeroTier address derived from the public key by way of a proof of work based hash function.

## COMMANDS

When command arguments call for a public or secret (full) identity, the identity can be specified as a path to a file or directly on the command line.

 * `help`:
   Display help. (Also running with no command does this.)

 * `generate` [secret file] [public file] [vanity[,vanity...]] [threads|auto] [options]:
   Generate one or more ZeroTier identities. With no vanity prefix, generation remains a single identity operation. Vanity searches use multiple workers; the default `auto` setting benchmarks worker counts and chooses the fastest observed count. On Linux, while searching, idtool reports available CPU frequency and thermal-throttle counters, and reduces the worker count after sustained throughput loss under thermal pressure. This monitor is best effort and only reads kernel data exposed under `/sys`.

   Prefixes are hexadecimal, up to 10 characters. A dot (`.`) matches one numeric hex digit (`0`–`9`); `g`, `i`, `o`, `s`, `t`, and `z` are accepted as hexleet aliases for `6`, `1`, `0`, `5`, `7`, and `2`. Multiple comma-separated prefixes and a prefix file are supported. `--vanity <prefixes>` and `--prefix-file <file>` allow searches without placeholder output paths. Prefix files accept whitespace-separated entries, blank lines, and `#` comments.

   Options: `--threads <n|auto>`, `--count <n>`, `--prefix-file <file>`, `--estimate`, and `--timing-file <file>`. The default timing profile is stored under `~/.cache/zerotier-idtool/vanity-timing.log` on Linux; `--timing-file` selects another path. `--estimate` reports the estimated success probability and uses recorded timing profiles to estimate time.

   With output paths and `--count` greater than one, each output filename is made unique using the generated address. Without output paths, generated secret identities are written to STDOUT.

 * `validate` <identity, only public part required>:
   Locally validate an identity's key and proof of work function correspondence.

 * `getpublic` <full identity with secret>:
   Extract the public portion of an identity.secret and print to STDOUT.

 * `sign` <full identity with secret> <file to sign>:
   Sign a file's contents with SHA512+ECC-256 (ed25519). The signature is output in hex to STDOUT.

 * `verify` <identity, only public part required> <file to check> <signature in hex>:
   Verify a signature created with `sign`.

 * `mkcom` <full identity with secret> [id,value,maxdelta] [...]:
   Create and sign a network membership certificate. This is not generally useful since network controllers do this automatically and is included mostly for testing purposes.

## EXAMPLES

Generate and dump a new identity:

    $ zerotier-idtool generate

Generate and write a new identity, both secret and public parts:

    $ zerotier-idtool generate identity.secret identity.public

Generate a vanity address that begins with the hex digits "beef" (this will take a while!):

    $ zerotier-idtool generate beef.secret beef.public beef

Generate the same vanity address using 8 worker threads:

    $ zerotier-idtool generate beef.secret beef.public beef 8

Generate an address starting with a numeric first digit and either `beef` or `cafe`:

    $ zerotier-idtool generate --vanity '.,beef,cafe' --threads auto

Generate several identities from prefixes listed in a file:

    $ zerotier-idtool generate --prefix-file prefixes.txt --count 3 --threads 4

Estimate a prefix search using the saved timing profiles:

    $ zerotier-idtool generate --vanity beef --estimate

Sign a file with an identity's secret key:

    $ zerotier-idtool sign identity.secret last_will_and_testament.txt

Verify a file's signature with a public key:

    $ zerotier-idtool verify identity.public last_will_and_testament.txt

## COPYRIGHT

(c)2011-2016 ZeroTier, Inc. -- https://www.zerotier.com/ -- https://github.com/zerotier

## SEE ALSO

zerotier-one(8), zerotier-cli(1)
