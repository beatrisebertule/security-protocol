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

## Bugs

Any assigned smart-card can open any vehicle.

## How to run

### Run normally

`make runsim`

### Run Tests

`make run-tests`
