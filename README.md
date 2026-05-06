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

## Bugs

Any assigned smart-card can open any vehicle.

## How to run

### Run normally

`make runsim`

### Run Tests

`make run-tests`
