# Vehicle Rental Smart Card System

A smart-card based vehicle rental system written in **Java Card** and **Java**. A customer's rental card authenticates to company terminals, gets a vehicle assigned, unlocks that vehicle, and records mileage, all protected by a custom security protocol built on ECDSA P-256 signatures and certificates.

The whole system runs locally on a simulated smart card ([jCardSim](https://jcardsim.org/)), so no physical card or reader is needed.

---

## Components

| Component | Location | Role |
| --- | --- | --- |
| **Card applet** | `RentalApplet/src/applet` | Java Card applet on the customer's card. Stores keys, PIN, card state, vehicle assignment and mileage. |
| **Personalization terminal** | `RentalTerminal/src/terminal/personalization` | Loads keys, certificate and PIN onto a blank card, then issues it to a customer. |
| **Reception terminal** | `RentalTerminal/src/terminal/reception` | Online desk terminal. Mutual authentication, PIN check, blocklist, vehicle assignment and mileage payment. |
| **Vehicle terminal** | `RentalTerminal/src/terminal/vehicle` | Offline terminal in the car. Checks the card's assignment token, opens the vehicle, updates mileage and signs the return. |
| **Backend** | `RentalTerminal/src/terminal/backend` | Simulated company backend. Holds the master signing key, customers, vehicles, blocklist and audit log. |
| **Simulator** | `RentalTerminal/src/terminal/simulation` | Interactive CLI that ties everything together. |

---

## Security design

**Trust model.** The company holds a master key pair. Every card and every terminal gets its own EC P-256 key pair plus a certificate signed by the master key. Both sides verify each other's certificate before trusting anything.

**Mutual authentication (reception terminal).**
1. The card sends a fresh 16-byte nonce. The terminal signs it and returns its certificate. The card verifies both.
2. The customer enters a PIN. The terminal sends a SHA-256 hash bound to the session nonce, so the PIN hash cannot be replayed. After 3 wrong attempts the card locks.
3. The terminal sends its own nonce. The card signs it and returns its certificate. The terminal verifies both.

**Vehicle assignment.** The card signs a request for a vehicle. The backend signs an assignment token that binds the card's public key to the vehicle ID and rental period, and the card stores it.

**Opening a vehicle (offline).** The vehicle terminal checks the backend-signed assignment token, then challenges the card to sign it together with a fresh nonce. This proves the card that presents the token is the card it was issued to.

**Mileage and return.** Mileage updates use a strictly increasing sequence number to stop rollback and replay. On return, the card signs a receipt with the vehicle ID and final mileage. Unpaid mileage blocks new rentals until it is settled at reception.

**Card lifecycle.** `BLANK → PERSONALIZED → ISSUED → ASSIGNED`, plus `BLOCKED` (lost/stolen, PIN locked, or backend blocklist) and `END_OF_LIFE`. Each command is only accepted in the states where it makes sense.

---

## Getting started

### Requirements

- Java JDK 8 or newer
- `make`
- `tmux` (only for `make runsim`)

Everything else (Java Card Kit 2.2.1, jCardSim, JLine, PIT, Randoop) is bundled in `util/`.

### Run the simulator

```bash
make runsim
```

This opens a tmux session with the interactive simulator on the left and live audit and verbose logs on the right. To run without tmux:

```bash
make runsim-plain
```

Simulator commands:

| Command | Description |
| --- | --- |
| `new` | Create, personalize and issue a new card |
| `cards` | List all cards |
| `use <cardId>` | Switch the active card |
| `reception` | Open a reception terminal session (authenticate, assign vehicle, pay mileage) |
| `vehicle` | Open a vehicle terminal session (unlock, drive, return) |
| `status` | Show vehicles, customers and cards |
| `log` | Print the audit log |
| `help` / `exit` | Show commands / quit |

You can also run each terminal on its own with `make runreception` or `make runvehicle`.

---

## Testing

```bash
make test
```

Builds everything from scratch and runs all test suites, then prints a summary (245 tests at the time of writing):

| Suite | What it covers |
| --- | --- |
| `AppletTest` | Applet commands, state transitions and PIN handling |
| `InfrastructureTest`, `ResultLoggingTest` | Utilities, encoding and logging |
| `QuickTest` | End-to-end happy path |
| `ProtocolTest` | Authentication, assignment and mileage protocol steps |
| `ReceptionTerminalTest`, `VehicleTerminalTest` | Terminal behaviour, including failure paths |
| `AdversarialTest` | Attacks from a **malicious terminal** (nonce replay, skipped auth or PIN, forged vehicle token, mileage rollback) and a **malicious card** (fake certificate, corrupted signature, forged vehicle challenge, fake return receipt) |

Mutation testing with [PIT](https://pitest.org/):

```bash
make mutation          # report written to pitest-report/index.html
make mutation THREADS=4
```

---

## Project structure

```
RentalApplet/src/applet/        Java Card applet (card side)
  RentalCardApplet.java         APDU dispatch and state checks
  CryptoUtil.java               Keys, nonces, ECDSA signing and verification
  PinManager.java               PIN storage, nonce-bound verification, try counter
  *Handler.java                 Personalization, vehicle and admin commands
RentalTerminal/src/terminal/    Terminals, backend and simulator (Java side)
  backend/  personalization/  reception/  vehicle/  simulation/
  util/                         APDU communication and crypto helpers
  logging/                      Audit log and terminal output
  test/                         Test suites
util/                           Bundled tools and libraries
Makefile                        Build, run and test targets
```
