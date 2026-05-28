# vehicle-rental-smartcard

## JavaCard documentation

[JavaCard Docs](https://pinpasjc.win.tue.nl/docs/apis/jc222/index.html)

## Entities

- Smart-card
- Backend
- Reception Terminal
- Personalization Terminal
- Vehicle Terminal

## Protocols

- Mutual Auth (Reception, Smart-card)

- Vehicle Selection (Julianne)
- Vehicle Return (Sarah)

- Vehicle Opening (Mutual Auth) (Marcelo)
- Mileage Update (Sarah)

## Features added

### Offline vehicle audit log

Vehicle terminals operate without a backend connection during normal use. All security-relevant events - successful vehicle opens, failed open attempts (wrong vehicle, tampered token, wrong state), and mileage updates - are recorded in a local log on the vehicle terminal.

When the customer returns the vehicle, the vehicle terminal syncs its accumulated local log to the backend as part of the return protocol. This means:

- Failed access attempts while parked are captured even though the vehicle is offline at the time.
- The backend receives a complete audit trail only after the vehicle is returned.
- Until return, the log is local to the vehicle terminal and not visible to the backend.

The sync is triggered by calling `VehicleTerminal.flushLogsToBackend(BackendSystem)` after a successful `returnVehicle()`. In the interactive simulator this happens automatically.

Also, we have added the audit log to reception terminal, for compatibility, it flushes every so often to avoid having to transfer traffic every time a new event is created (mroe efficienty)

### Blocking smart-cards.

Backend adds the blocked smart-card to a list, which gets pulled by the receptions terminals, which them issue the blocking message to the smart-card when it next interacts with them

## Bugs

Any assigned smart-card can open any vehicle.

## Memory in the RentalApplet

Java Card has two kinds of memory: EEPROM (persistent) and RAM (transient).

### EEPROM - persistent across power cycles

Allocate with `new`. Survives card power-off and resets.

```java
// Instance fields allocated in the constructor
cardId = new byte[CARD_ID_LENGTH];          // RentalCardApplet
customerId = new byte[CUSTOMER_ID_LENGTH];
assignedVehicleId = new byte[VEHICLE_ID_LENGTH];
rentalPeriod = new byte[RENTAL_PERIOD_LENGTH];
expiryDate = new byte[EXPIRY_DATE_LENGTH];

certificate = new byte[AppletConstants.MAX_CERT_LENGTH];    // CryptoManager
assignmentToken = new byte[AppletConstants.MAX_ASSIGN_LENGTH];

pinHash = new byte[AppletConstants.PIN_HASH_LENGTH];        // PinManager
```

Primitive instance fields (`state`, `mileage`, `counter`, etc.) are also EEPROM.

Write to EEPROM with `Util.arrayCopy` or `Util.arrayFill`. For writes that must be atomic (all-or-nothing), use `JCSystem.beginTransaction()` / `JCSystem.commitTransaction()`. For non-critical writes where performance matters more than atomicity, use `Util.arrayCopyNonAtomic` / `Util.arrayFillNonAtomic`.

### RAM - transient, cleared automatically

Allocate with `JCSystem.makeTransientByteArray` (or the boolean/short variants). Never survives a card reset; `CLEAR_ON_DESELECT` is also wiped when the applet is deselected.

```java
// Cleared when the applet is deselected
sessionFlags = JCSystem.makeTransientBooleanArray((short) 2, JCSystem.CLEAR_ON_DESELECT);  // RentalCardApplet

lastNonce = JCSystem.makeTransientByteArray(AppletConstants.NONCE_LENGTH, JCSystem.CLEAR_ON_DESELECT);  // CryptoManager
tempBuf   = JCSystem.makeTransientByteArray((short) 320, JCSystem.CLEAR_ON_DESELECT);
sigBuf    = JCSystem.makeTransientByteArray((short) 80,  JCSystem.CLEAR_ON_DESELECT);
```

Use RAM for session-scoped state (auth flags, nonces, scratch buffers). EEPROM writes are slow and wear out the card, so offload any temporary computation to RAM buffers.

### When to use each

| Use EEPROM for                         | Use RAM for                                |
| -------------------------------------- | ------------------------------------------ |
| Card identity (`cardId`, `customerId`) | Auth session flags (`sessionFlags`)        |
| Cryptographic keys and certificates    | Nonces (`lastNonce`)                       |
| Assignment token                       | Scratch/temp buffers (`tempBuf`, `sigBuf`) |
| Mileage and state                      | Any data that should not outlive a session |

## How to run

### Run normally

`make runsim`

### Run Tests

`make run-tests`
