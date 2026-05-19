# Overall notes with programming with JavaCard from Erik

- No `new ... ` or `makeTransientByteArray(..)` expect for the initalization phase
- Use a lot of `(short)` casts.
- No `strings` or `clone()`
- Use a lot of begin transactions and close transactions

## Notes on vehicle selection'

- Default value of a card is false, so we want the booleans the other way around, to make the card termerisitatnet. So notblocked etc..

## Issues

- [x] A card can now open any vehicle
- [ ] All the exceptions should be replaced by public class Result<T> { public final boolean success; public final T value; public final SecurityException error;}
- [x] Implement a ReceptionTerminalBase for testing
- [ ] Implement a VehicleTerminalBase for testing JULIANNE
- [ ] Implement a PersonalizationTerminalBase for testing JULIANNE
- [ ] Check we are using the correct card simulator Erik was talking about. I have a feeling we should use JCSystem everywhere but im unsure.
- [ ] Decide whether we want to include payment or let it exist as a seperate function that can be implemented on a lter time.
- [ ] Split up the cardCOmm class. We need a base an implementation for the different terminals.
- [ ] Add general comments in every function /\*\* \*\*/ with optinal @param & @return for every public or portected function
- [ ] Look at the abracadaca code in the common folder.
- [ ] Fixing the log's

## Need to check and confirm the folowing protocols on working correctly:

- [ ] Figure 2: Mileage update protocol during driving
- [ ] Figure 3: Vehicle return protocol
- [ ] Figure 4: Mutual authentication reception, smart-card and smart-card’s user
- [x] Figure 5: Vehicle selection and assignment phase
  - Done with some few issues left
  - [ ] The above issues will have a lot of impact on this protocol and needs to be revisited afterwards.
  - [ ] Add the comments above the function
- [ ] Figure 6: Vehicle opening protocol
