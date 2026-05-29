# Overall notes with programming with JavaCard from Erik

- No `new ... ` or `makeTransientByteArray(..)` expect for the initalization phase
- Use a lot of `(short)` casts.
- No `strings` or `clone()`
- Use a lot of begin transactions and close transactions

## Notes on vehicle selection'

- Default value of a card is false, so we want the booleans the other way around, to make the card termerisitatnet. So notblocked etc..

## Issues

- [x] A card can now open any vehicle
- [x] All the exceptions should be replaced by public class Result<T> { public final boolean success; public final T value; public final SecurityException error;} - Marcelo
- [x] Implement a ReceptionTerminalBase for testing
- [x] Check we are using the correct card simulator Erik was talking about. I have a feeling we should use JCSystem everywhere but im unsure. - Marcelo
- [x] Implement a VehicleTerminalBase for testing JULIANNE
- [x] Implement a PersonalizationTerminalBase for testing JULIANNE
- [x] Decide whether we want to include payment or let it exist as a seperate function that can be implemented on a lter time. - Marcelo RANODM PAYMENTO
- [x] Split up the cardCOmm class. We need a base an implementation for the different terminals. - Juliana --> Idk what i was thinking here it is a file of only 100 lines
- [ ] Add general comments in every function /\*\* \*\*/ with optinal @param & @return for every public or portected function. Javadoc - SARAH NANJANI
- [ ] OVERVIEW OF GENERAL CODE - JULES
- [x] Look at the abracadaca code in the common folder. - Marcelo
- [ ] Fixing the log's - BEA
- [x] WHAAAA FORGOT I cannot read important!!!! transactions, they need to be implemented, otherwise people can just take a card out, needs to be implemented in all terminals. - Sarah

## Need to check and confirm the folowing protocols on working correctly:

- [x] Figure 2: Mileage update protocol during driving
- [x] Figure 3: Vehicle return protocol
- [x] Figure 4: Mutual authentication reception, smart-card and smart-card’s user - BEA
- [x] Figure 5: Vehicle selection and assignment phase
  - Done with some few issues left
  - [ ] The above issues will have a lot of impact on this protocol and needs to be revisited afterwards.
  - [ ] Add the comments above the function
- [x] Figure 6: Vehicle opening protocol - MARCELO
- [x] New terminal output - display protocol steps with numbers (mutual auth example) - MARCELO
- New terminal output, link numbers with protocol pdf DO AT THE END OF PROJECT (in case the pdf changes)
