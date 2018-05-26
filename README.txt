copystrap: copy encrypted data to a new computer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
copystrap is a collection of shell and Python scripts for Unix to
conveniently copy data in an end-to-end encrypted way to a newly installed
computer. The reason why copystrap is more convenient than rsync or scp is
that rsync and scp need working SSH client credentials (e.g. private keys or
passwords) on the target computer, and they may also need an intermediate
computer in many firewall setups.

copystrap contains the following scripts:

* ecptrsh: Uses https://transfer.sh/ to copy the data and store it
  temporarily. Files uploaded to transfer.sh are end-to-end encrypted with
  ephemeral keys.

  Abberviation of: Encrypted Copy using TRansfer.SH.

  If the website https://transfer.sh/ is down, or you don't even want to
  upload encrypted files to a thrid-party site, use ecplmdr instead.

  To send, download ecptrsh first: run any of:

    $ wget -nv https://github.com/pts/copystrap/raw/master/ecptrsh
    $ curl -LO https://github.com/pts/copystrap/raw/master/ecptrsh

  To send, run:

    $ sh ecptrsh send FILENAME

  To receive, run any of:

    $ sh ecptrsh receive >OUT
    $ wget -qO- https://github.com/pts/copystrap/raw/master/ecptrsh | sh >OUT
    $ curl -Ls  https://github.com/pts/copystrap/raw/master/ecptrsh | sh >OUT
    $ busybox wget -qO- https://github.com/pts/ecptrsh/raw/master/ecptrsh | busybox sh >OUT

* ecplmdr: Uses a USB pen drive or any other manual file copy method to copy
  the data and store it temporarily. Files copied between computers are
  end-to-end encrypted with ephemeral keys.

  Abbreviaton of: Encrypted Copy using a Locally-Mounted Drive.

  Start the receiver first. The default receive locations (DIR) are any
  writable mounted filesystems within /media/ .

  To receive, mount your USB pen drive to DIR, and run any of:

    $ sh ecplmdr receive --in DIR >OUT
    $ sh ecplmdr receive >OUT
    $ wget -qO- https://github.com/pts/copystrap/raw/master/ecplmdr | sh >OUT
    $ curl -Ls  https://github.com/pts/copystrap/raw/master/ecplmdr | sh >OUT
    $ busybox wget -qO- https://github.com/pts/ecplmdr/raw/master/ecplmdr | busybox sh >OUT

  To send, download ecplmdr first: run any of:

    $ wget -nv https://github.com/pts/copystrap/raw/master/ecplmdr
    $ curl -LO https://github.com/pts/copystrap/raw/master/ecplmdr

  To send, move the USB pen drive to the sender, mount it to DIR, and run any of:

    $ sh ecplmdr send FILENAME
    $ sh ecplmdr send --in DIR FILENAME

Why is copystrap more convenient than SSH-based copy tools such as rsync and
scp?

* On a newly installed target computer, the SSH client credentials (e.g.
  private keys or passwords) may not be available.

* Firewall settings (e.g. those at home or in hotels) may prevent the source
  and target computers to connect to each other using SSH directly, thus a
  intermediate computer (with sshd running) is needed, and then extra encryption is
  needed so the data is not stored in plain text on the intermediate computer.

Why is copystrap more secure than copying the file to a USB pen drive?

* With copystrap all files being transferred are end-to-end encrypted, and
  only the source and the target computer see the plaintext.

Why is copystrap more convenient than copying the file to a USB pen drive?

* copystrap does the encryption with random ephemeral keys, so the user
  doesn't have to invent (or type or copy-paste) temporary passphrases.

Dependencies of copystrap:

* A Unix system: Linux, macOS, FreeBSD or something similar.
* (for ecptrsh) Python 2.7 or 2.6.
* (for ecplmdr) Python 2.7, 2.6, 2.5 or 2.4.
  If Python 2.4 is used, then the external hashlib package (from PyPi) also
  has to be installed.
* A Bourne shell. Bash, Zsh, Dash and Busybox sh all work.
* (optional) curl or wget for the single-command receiver.
* (for ecptrsh): The https://transfer.sh/ website up, working, and reachable
  from both the source and target computers without a HTTP proxy.

copystrap uses the following crypto:

* Curve25519 for key exchange (random emphemeral encryption key
  generation) between the sender and the receiver.
* ChaCha20 for encrypting and decrypting with the emphemeral key.
* SHA-256 for detecting corruption and modification.

Steps of a copystrap run:

1. (manual) The receiver is started.

2. The receiver generates a Curve25519 public key.

3. (manual) The receiver's public key is copied to the sender.

4. The sender also generates a Curve25519 public key, and encrypts the data
   with the emphemeral key.

5. The sender exits, forgetting all keys.

6. (manual) The encrypted data and the sender's public key are copied to the
   receiver.

7. The receiver decrypts the encrypted data and prints the plaintext to
   standard output.

8. The receiver exits, forgetting all keys.

Is it possible to transfer a large data blob with copystrap?

* The encryption overhead on data size is small (less than 200 bytes).

* https://transfer.sh/ has a file size limit of 5 GB.

* Your USB pen drive may not have enough free space available.

* The pure Python implementation of ChaCha20 may be too slow for data longer
  than a few MB.

* copystrap keeps 4 copies of the data in memory, so the source or target
  computer may run out of local memory.

__END__
