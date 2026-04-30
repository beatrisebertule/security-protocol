# Overall notes with programming with JavaCard from Erik

- No ```new ... ``` or ```makeTransientByteArray(..)``` expect for the initalization phase
- Use a lot of ```(short)``` casts.
- No ```strings``` or ```clone()```
-  Use a lot of begin transactions and close transactions


## Notes on vehicle selection'

- The protocol we now have doesn't specifiy pin input --> It is splitted to another protocol, we have now that we first authenticate and after vehicle selection, better would be to do other way around, you want to decrease that specific time as much as possible, but on the other end, you first want to be authenticated ofc...
- Default value of a card is false, so we want the booleans the other way around, to make the card termerisitatnet. So notblocked etc..


