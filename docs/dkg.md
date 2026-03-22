# DKG Wrapper

The `dkls-wrapper` includes a wrapper for DKG setup that is intended for use in
a mobile app. The problem is simple: DKG is secure if you're starting from a set
of nodes with established public keys. But if you're starting from scratch how
do you determine the initial set of public keys? In particular, if a user who
*isn't* a cryptographer is setting up a new key, how can we guide them through
the process in a way that is both secure (for some definition of security) and
easy to use?

This document describes how this setup is intended to work to a cryptographic /
security-minded audience.

## Assumptions

In order to solve this problem we introduce a setup ceremony, with the following
assumptions:

1. The user is using a set of (> 1) mobile devices or services.
2. There is a broadcast channel connecting these devices.
3. The devices can display a QR code to be scanned by another device.
    1. Alternatively, there is some secure channel for a short string (e.g.
       copy-and-paste via command line, hand copying but verifying each
       character etc).
    2. For this document we will say "scan a QR code" for any secure transfer.
4. Devices may be corrupted and the network may be adversarial, but in order to
   guarantee security we require that either the network is non-adversarial or
   that each device scans the QR code of at least one non-corrupt device.


## The Ceremony

The setup ceremony is relatively simple and solves the problem by making some
natural assumptions on user behaviour.

1. The user starts with an initial device, on which they enter network and key
   parameters (e.g. broadcast channel id, threshold, etc.)

2. The initial device generates a QR code containing that includes the necessary
   parameters and its verification key.

3. For each device the user wishes to add to the DKG:
    1. The user scans the QR code displayed by the initial device with the new
       device.
    2. The new device sends a "join" message to the broadcast channel with its
       verification keys.
    3. When existing devices receive a "join" message (that passes some basic
       verifications) they add the new device's verification key to their list
       of keys, and send out a "confirm" message with their updated list of
       keys, signed by their signing key.
    4. When the new device receives a confirmation message, it checks only that
       it's in the list and that the device it scanned is in the correct
       location in the list. If so, it accepts the list of devices and its
       position.
    5. All devices wait for signatures from all other devices on the list before
       proceeding, at which point they show their QR code for scanning.

4. At any time a user may scan the QR code of a device that is already in the
   list to verify its verification key.

5. Once a threshold number of devices is reached, the user can choose to start
   the DKG process itself. To do so, one device sends out a "start" message that
   includes all of the parameters needed, signed by its signing key. All other
   devices check that the parameters match the last accepted set. If so, they
   begin the DKG proper. If not, they show an error to the user.


A few notes on this process:
* It is assumed that each device shows a list of accepted devices to the user,
  and that the user will notice if a device name is added or removed.
* It is *not* assumed that the user will notice if a verification key is
  incorrect.
* There is no way to remove a device once added. To do so the user must restart
  the ceremony.
* There are a myriad of ways this process can fail. Rather than trying to be
  robust to them, we instead try to give the user an error so they can simply
  restart the process. Our goal is to make the normal case easy and the failure
  case obvious but not robust.

## Security

Since we've assumed the user will notice if unauthorized devices are added to
the list or authorized devices are missing, we limit security to ensuring that
the keys are correct since in practice users are unlikely to verify keys by
hand. Obviously, if a user scans all of the other devices using the QR scanner
then they will have verified all verification keys are correct and security is
guaranteed. While we recommend this for highest security, it's impractial for
most users. Instead, we rely on a slightly stronger assumption: either the
network is non-adversarial, or each device scans at least one non-corrupt
device.

Let's take the first case: if a new device scans the QR code of a corrupt
device, the corrupt device may try to convince the new device to join the DKG
with the incorrect verification key for a device. In this case, the new device
will receive conflicting confirmation messages from the existing non-corrupt
devices, which will produce an error.

If the network is adversarial but the device scans at least one non-corrupt
then it must agree with the device list of that non-corrupt device. Through an
inductive argument it can be seen that all non-corrupt devices will then agree
on the device list.

## State Machine

At current, the Rust DKG wrapper uses a state machine under the hood to manage
the process. I wrote it this way so you could reason about what to do at each
step but I'm honestly not sure if this makes it more or less complex. In any
case, here's what the state machine is like now.

![DKG State Machine Diagram](dkg_state_machine.svg)
[DrawIO Link](https://drive.google.com/file/d/1i9_P6F7Q--ZZBukZVQ6v8U_jqQ5spEPL/view?usp=sharing)

