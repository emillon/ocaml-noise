ocaml-noise
===========

OCaml implementation of the [Noise Protocol
Framework](https://noiseprotocol.org/).

Not ready for primetime.

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

Resources
---------

- [Trevor Perrin, RWC 2018](https://www.youtube.com/watch?v=3gipxdJ22iM)
- [an explanation by David Wong](https://www.youtube.com/watch?v=ceGTgqypwnQ)
- [the spec itself](https://noiseprotocol.org/noise.html)
