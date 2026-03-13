# vehicle-rental-smartcard

## JavaCard documentation

[JavaCard Docs](https://pinpasjc.win.tue.nl/docs/apis/jc222/index.html)

To interact:
[Javacard API docs](https://jcardsim.org/docs/quick-start-guide-simulator-api)

## JavaCard This project includes a simple JavaCard applet plus two terminals to

interact with that applet running on a simulated smartcard using
JCardSim (https://jcardsim.org)

- CalcApplet/src/applet/CalcApplet.java

  is the (somehat silly) applet that provides the functionality of a
  simple calculator

- CalcTerminal/src/terminal/QuickTest.java

  is a bare bones terminal to exchange APDUs with the applet

- CalcTerminal/src/terminal/CalcTerminal.java

  provides a fancier GUI to interact with the applet. Under the
  hood this of course also communicates with APDUs.

Other files and directories included:

- Makefile: a makefile to compile and run all the applications above.
  It should work if you have just about any version of Java installed.

- util: this directory provides all the libaries (jar files) needed to
  run & compile things, incl. the Java Card Development Kit 2.2.1,
  the JCardSim simulator, and Global Platform .

Global Platfom (https://javacard.pro/globalplatform/) won't be
needed really, as it's only needed to install code on acctual
physical smartcards.

GP

JCardSim supports up to JavaCard version 3.0.4 but it is probably
easier (and less confusing) to stick to the 2.2.1 functionality.
