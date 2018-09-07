ocaml-noise
===========

OCaml implementation of the [Noise Protocol
Framework](https://noiseprotocol.org/).

Not ready for primetime.

More precisely, some primitives are implemented in an ad hoc manner. This passes
a good amount of test vectors, but this has not been properly fuzzed and there
are no countermeasures with respect to side channel attacks.

What is this NOT?
-----------------

This is **not** an implementation of a full cryptographic protocol that you can
drop into your application and have secure channels.

What is this?
-------------

This is an implementation of the Noise Protocol Framework. It consists of
building bricks that can be used to create a secure cryptographic protocol.

Because of the way Noise works, it is possible to process messages in full
without dealing with I/O or buffering. So, this library only deals with the
handshake and encrypting/decrypting payloads.

How to use this?
----------------

Refer to the examples in `test/examples/` for an example, but basically:

- pick a protocol
- import or generate the relevant keys on each side
- create initial states using `Noise.State.make` and
  `Noise.Protocol.initialize`
- drive the handshake using `Noise.Protocol.read_message` and
  `Noise.Protocol.write_message`
- check that the handshake is completed (see `Noise.State.handshake_hash`)
- send transport messages using `Noise.Protocol.read_message` and
  `Noise.Protocol.write_message`

Resources
---------

- [Trevor Perrin, RWC 2018](https://www.youtube.com/watch?v=3gipxdJ22iM)
- [an explanation by David Wong](https://www.youtube.com/watch?v=ceGTgqypwnQ)
- [the spec itself](https://noiseprotocol.org/noise.html)
