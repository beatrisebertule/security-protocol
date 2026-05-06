# Path to the Java Card Development Kit
JC_HOME=util/java_card_kit-2_2_1

# Version of JCardSim to use
JCARDSIM=jcardsim-3.0.4-SNAPSHOT

# Beware that only JCardSim-3.0.4-SNAPSHOT.jar includes the classes
# AIDUtil and CardTerminalSimulator, so some of the code samples on
# https://jcardsim.org/docs do not work with older versions
#    JCARDSIM=jcardsim-2.2.1-all
#    JCARDSIM=jcardsim-2.2.2-all

# Classpath for JavaCard code, ie the smartcard applet; this includes
# way more than is probably needed
JC_CLASSPATH=${JC_HOME}/lib/apdutool.jar:${JC_HOME}/lib/apduio.jar:${JC_HOME}/lib/converter.jar:${JC_HOME}/lib/jcwde.jar:${JC_HOME}/lib/scriptgen.jar:${JC_HOME}/lib/offcardverifier.jar:${JC_HOME}/lib/api.jar:${JC_HOME}/lib/installer.jar:${JC_HOME}/lib/capdump.jar:${JC_HOME}/samples/classes:${CLASSPATH}

JCSIM_JAR=util/jcardsim/${JCARDSIM}.jar
JLINE_JAR=util/jline/jline-3.25.1.jar

# ============================================================
# Default: build everything
# ============================================================

all: rental-applet rental-terminal

# ============================================================
# Rental applet (JavaCard side)
# Compiled against JCardSim jar (provides LENGTH_EC_FP_256)
# ============================================================

rental-applet: RentalApplet/bin/applet/RentalCardApplet.class

RentalApplet/bin/applet/RentalCardApplet.class: \
		RentalApplet/src/applet/RentalCardApplet.java \
		RentalApplet/src/applet/CryptoManager.java \
		RentalApplet/src/applet/PinManager.java \
		RentalApplet/src/applet/AppletConstants.java
	mkdir -p RentalApplet/bin
	javac -d RentalApplet/bin -cp ${JCSIM_JAR} \
		RentalApplet/src/applet/AppletConstants.java \
		RentalApplet/src/applet/CryptoManager.java \
		RentalApplet/src/applet/PinManager.java \
		RentalApplet/src/applet/RentalCardApplet.java \
		RentalApplet/src/applet/AppletTest.java

# ============================================================
# Rental terminal (standard Java side)
# ============================================================

TERMINAL_SOURCES= \
	RentalTerminal/src/terminal/common/ByteUtil.java \
	RentalTerminal/src/terminal/common/CardComm.java \
	RentalTerminal/src/terminal/common/CryptoUtil.java \
	RentalTerminal/src/terminal/common/ProtocolConstants.java \
	RentalTerminal/src/terminal/backend/Vehicle.java \
	RentalTerminal/src/terminal/backend/Customer.java \
	RentalTerminal/src/terminal/backend/BackendSystem.java \
	RentalTerminal/src/terminal/personalization/PersonalizationTerminal.java \
	RentalTerminal/src/terminal/reception/ReceptionTerminalBase.java \
	RentalTerminal/src/terminal/reception/ReceptionTerminal.java \
	RentalTerminal/src/terminal/reception/TestReceptionTerminal.java \
	RentalTerminal/src/terminal/vehicle/VehicleTerminal.java \
	RentalTerminal/src/terminal/test/InfrastructureTest.java \
	RentalTerminal/src/terminal/test/QuickTest.java \
	RentalTerminal/src/terminal/test/ProtocolTest.java \
	RentalTerminal/src/terminal/simulator/SystemSimulator.java

rental-terminal: RentalApplet/bin/applet/RentalCardApplet.class
	mkdir -p RentalTerminal/bin
	javac -d RentalTerminal/bin \
		-cp ${JCSIM_JAR}:${JLINE_JAR}:RentalApplet/bin \
		${TERMINAL_SOURCES}

# ============================================================
# Tests
# ============================================================

# Run all tests (applet unit tests + infrastructure tests + integration tests)
run-tests: rental-applet rental-terminal
	@echo ""
	@echo "=== Applet unit tests ==="
	java -cp ${JCSIM_JAR}:RentalApplet/bin applet.AppletTest
	@echo ""
	@echo "=== Infrastructure tests ==="
	java -cp ${JCSIM_JAR}:RentalTerminal/bin terminal.test.InfrastructureTest
	@echo ""
	@echo "=== Integration (QuickTest) ==="
	java -cp ${JCSIM_JAR}:RentalTerminal/bin:RentalApplet/bin terminal.test.QuickTest
	@echo ""
	@echo "=== Protocol / security tests ==="
	java -cp ${JCSIM_JAR}:RentalTerminal/bin:RentalApplet/bin terminal.test.ProtocolTest
	@echo ""
	@echo "=== All test suites complete ==="

# Convenience alias
test: run-tests

# ============================================================
# Interactive CLIs
# ============================================================

runreception: rental-applet rental-terminal
	java -cp ${JCSIM_JAR}:RentalTerminal/bin:RentalApplet/bin terminal.reception.ReceptionTerminal

runvehicle: rental-applet rental-terminal
	java -cp ${JCSIM_JAR}:RentalTerminal/bin:RentalApplet/bin terminal.vehicle.VehicleTerminal

runsim: rental-applet rental-terminal
	java -cp ${JCSIM_JAR}:${JLINE_JAR}:RentalTerminal/bin:RentalApplet/bin terminal.simulator.SystemSimulator

# ============================================================
# Legacy CalcApplet / CalcTerminal (reference only)
# ============================================================

applet: CalcApplet/bin/CalcApplet.class

CalcApplet/bin/CalcApplet.class: CalcApplet/src/applet/CalcApplet.java
	javac -d CalcApplet/bin -cp ${JC_CLASSPATH}:CalcTerminal/src CalcApplet/src/applet/CalcApplet.java

quicktest: CalcTerminal/bin/terminal/QuickTest.class

CalcTerminal/bin/terminal/QuickTest.class: CalcTerminal/src/terminal/QuickTest.java
	javac -d CalcTerminal/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CalcApplet/bin CalcTerminal/src/terminal/QuickTest.java

runquicktest:
	# Sends some sample APDUs to the CalcApplet
	java -cp util/jcardsim/${JCARDSIM}.jar:CalcTerminal/bin:CalcApplet/bin terminal.QuickTest

terminal: CalcTerminal/bin/terminal/CalcTerminal.class

CalcTerminal/bin/terminal/CalcTerminal.class: CalcTerminal/src/terminal/CalcTerminal.java
	javac -d CalcTerminal/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CalcApplet/bin:CalcTerminal/bin CalcTerminal/src/terminal/CalcTerminal.java

runterminal:
	# Runs the GUI terminal
	java -cp util/jcardsim/${JCARDSIM}.jar:CalcTerminal/bin:CalcApplet/bin terminal.CalcTerminal

# ============================================================

clean:
	rm -rf CalcApplet/bin/*
	rm -rf CalcTerminal/bin/*
	rm -rf RentalApplet/bin/*
	rm -rf RentalTerminal/bin/*
