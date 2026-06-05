# Path to the Java Card Development Kit
JC_HOME=util/java_card_kit-2_2_1

# Version of JCardSim to use
JCARDSIM=jcardsim-3.0.5-SNAPSHOT

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
PITEST_DIR=util/pitest
PITEST_CP=${PITEST_DIR}/pitest.jar:${PITEST_DIR}/pitest-command-line.jar:${PITEST_DIR}/pitest-entry.jar:${PITEST_DIR}/junit.jar:${PITEST_DIR}/hamcrest.jar:${PITEST_DIR}/commons-text.jar:${PITEST_DIR}/commons-lang3.jar

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
		RentalApplet/src/applet/CryptoUtil.java \
		RentalApplet/src/applet/PinManager.java \
		RentalApplet/src/applet/AppletConstants.java \
		RentalApplet/src/applet/PersonalizationHandler.java \
		RentalApplet/src/applet/VehicleHandler.java \
		RentalApplet/src/applet/AdminHandler.java
	mkdir -p RentalApplet/bin
	javac -d RentalApplet/bin -cp ${JCSIM_JAR}:${PITEST_DIR}/junit.jar:${PITEST_DIR}/hamcrest.jar \
		RentalApplet/src/applet/AppletConstants.java \
		RentalApplet/src/applet/CryptoUtil.java \
		RentalApplet/src/applet/PinManager.java \
		RentalApplet/src/applet/PersonalizationHandler.java \
		RentalApplet/src/applet/VehicleHandler.java \
		RentalApplet/src/applet/AdminHandler.java \
		RentalApplet/src/applet/RentalCardApplet.java \
		RentalApplet/src/applet/test/AppletTest.java \
		RentalApplet/src/applet/test/AppletTestJUnit.java

# ============================================================
# Rental terminal (standard Java side)
# ============================================================

TERMINAL_SOURCES= \
	RentalTerminal/src/terminal/TerminalBase.java \
	RentalTerminal/src/terminal/util/CardComm.java \
	RentalTerminal/src/terminal/util/ProtocolConstants.java \
	RentalTerminal/src/terminal/util/ByteUtil.java \
	RentalTerminal/src/terminal/util/CardUtil.java \
	RentalTerminal/src/terminal/util/CryptoUtil.java \
	RentalTerminal/src/terminal/util/TokenUtil.java \
	RentalTerminal/src/terminal/logging/LocalAuditLog.java \
	RentalTerminal/src/terminal/logging/Result.java \
	RentalTerminal/src/terminal/logging/TerminalOutput.java \
	RentalTerminal/src/terminal/logging/VerboseLogger.java \
	RentalTerminal/src/terminal/logging/messages/CardCommMessages.java \
	RentalTerminal/src/terminal/logging/messages/PersonalizationMessages.java \
	RentalTerminal/src/terminal/logging/messages/ReceptionMessages.java \
	RentalTerminal/src/terminal/logging/messages/VehicleMessages.java \
	RentalTerminal/src/terminal/backend/Vehicle.java \
	RentalTerminal/src/terminal/backend/Customer.java \
	RentalTerminal/src/terminal/backend/BackendSystem.java \
	RentalTerminal/src/terminal/personalization/PersonalizationTerminal.java \
	RentalTerminal/src/terminal/personalization/PersonalizationTerminalBase.java \
	RentalTerminal/src/terminal/reception/ReceptionTerminalBase.java \
	RentalTerminal/src/terminal/reception/ReceptionTerminal.java \
	RentalTerminal/src/terminal/test/TestReceptionTerminal.java \
	RentalTerminal/src/terminal/vehicle/VehicleTerminalBase.java \
	RentalTerminal/src/terminal/vehicle/VehicleTerminal.java \
	RentalTerminal/src/terminal/test/TestVehicleTerminal.java \
	RentalTerminal/src/terminal/test/InfrastructureTest.java \
	RentalTerminal/src/terminal/test/ResultLoggingTest.java \
	RentalTerminal/src/terminal/test/QuickTest.java \
	RentalTerminal/src/terminal/test/ProtocolTest.java \
	RentalTerminal/src/terminal/test/VehicleTerminalTest.java \
	RentalTerminal/src/terminal/test/ReceptionTerminalTest.java \
	RentalTerminal/src/terminal/test/AdversarialTest.java \
	RentalTerminal/src/terminal/test/ProtocolTestJUnit.java \
	RentalTerminal/src/terminal/test/AdversarialTestJUnit.java \
	RentalTerminal/src/terminal/test/VehicleTerminalTestJUnit.java \
	RentalTerminal/src/terminal/test/ReceptionTerminalTestJUnit.java \
	RentalTerminal/src/terminal/test/QuickTestJUnit.java \
	RentalTerminal/src/terminal/test/BackendSystemTest.java \
	RentalTerminal/src/terminal/test/BackendSystemTestJUnit.java \
	RentalTerminal/src/terminal/test/randoop/BackendSystemRandoopTest.java \
	RentalTerminal/src/terminal/simulation/SystemSimulator.java \
	RentalTerminal/src/terminal/simulation/ReceptionTerminalSimulator.java \
	RentalTerminal/src/terminal/simulation/VehicleTerminalSimulator.java

rental-terminal: RentalApplet/bin/applet/RentalCardApplet.class
	mkdir -p RentalTerminal/bin
	javac -d RentalTerminal/bin \
		-cp ${JCSIM_JAR}:${JLINE_JAR}:${PITEST_DIR}/junit.jar:${PITEST_DIR}/hamcrest.jar:RentalApplet/bin \
		${TERMINAL_SOURCES}

# ============================================================
# Tests
# ============================================================

# Run all tests (applet unit tests + infrastructure tests + integration tests)
test: clean rental-applet rental-terminal
	@echo ""
	@echo "=== Applet unit tests ==="
	@java -cp ${JCSIM_JAR}:RentalApplet/bin applet.test.AppletTest 2>&1 | tee /tmp/test_applet.txt
	@echo ""
	@echo "=== Infrastructure tests ==="
	@java -cp ${JCSIM_JAR}:RentalTerminal/bin terminal.test.InfrastructureTest 2>&1 | tee /tmp/test_infra.txt
	@echo ""
	@echo "=== Result logging tests ==="
	@java -cp ${JCSIM_JAR}:RentalTerminal/bin terminal.test.ResultLoggingTest 2>&1 | tee /tmp/test_result_logging.txt
	@echo ""
	@echo "=== Integration (QuickTest) ==="
	@java -cp ${JCSIM_JAR}:RentalTerminal/bin:RentalApplet/bin terminal.test.QuickTest 2>&1 | tee /tmp/test_quick.txt
	@echo ""
	@echo "=== Protocol / security tests ==="
	@java -cp ${JCSIM_JAR}:RentalTerminal/bin:RentalApplet/bin terminal.test.ProtocolTest 2>&1 | tee /tmp/test_protocol.txt
	@echo ""
	@echo "=== Vehicle terminal tests ==="
	@java -cp ${JCSIM_JAR}:RentalTerminal/bin:RentalApplet/bin terminal.test.VehicleTerminalTest 2>&1 | tee /tmp/test_vehicle.txt
	@echo ""
	@echo "=== Reception terminal tests ==="
	@java -cp ${JCSIM_JAR}:RentalTerminal/bin:RentalApplet/bin terminal.test.ReceptionTerminalTest 2>&1 | tee /tmp/test_reception.txt
	@echo ""
	@echo "=== Adversarial tests ==="
	@java -cp ${JCSIM_JAR}:RentalTerminal/bin:RentalApplet/bin terminal.test.AdversarialTest 2>&1 | tee /tmp/test_adversarial.txt
	@echo ""
	@echo "=== All test suites complete ==="
	@echo ""
	@echo "=== TOTAL RESULTS ==="
	@sed 's/\r$$//' util/summarize-tests.sh > /tmp/summarize-tests.sh
	@bash /tmp/summarize-tests.sh \
		"AppletTest:/tmp/test_applet.txt" \
		"InfrastructureTest:/tmp/test_infra.txt" \
		"ResultLoggingTest:/tmp/test_result_logging.txt" \
		"QuickTest:/tmp/test_quick.txt" \
		"ProtocolTest:/tmp/test_protocol.txt" \
		"VehicleTerminalTest:/tmp/test_vehicle.txt" \
		"ReceptionTerminalTest:/tmp/test_reception.txt" \
		"AdversarialTest:/tmp/test_adversarial.txt"
	@rm -f /tmp/summarize-tests.sh /tmp/test_*.txt

mutation: rental-applet rental-terminal
	@echo ""
	@echo "=== Mutation Testing (PIT) ==="
	java -cp ${PITEST_CP}:${JCSIM_JAR}:RentalApplet/bin:RentalTerminal/bin \
		org.pitest.mutationtest.commandline.MutationCoverageReport \
		--includeLaunchClasspath false \
		--classPath ${JCSIM_JAR},${PITEST_DIR}/junit.jar,${PITEST_DIR}/hamcrest.jar,RentalApplet/bin,RentalTerminal/bin \
		--targetClasses "applet.RentalCardApplet,applet.CryptoUtil,applet.PinManager,terminal.reception.ReceptionTerminalBase,terminal.vehicle.VehicleTerminalBase,terminal.backend.BackendSystem" \
		--targetTests "applet.AppletTestJUnit,terminal.test.ProtocolTestJUnit,terminal.test.AdversarialTestJUnit,terminal.test.VehicleTerminalTestJUnit,terminal.test.ReceptionTerminalTestJUnit,terminal.test.QuickTestJUnit,terminal.test.BackendSystemTestJUnit,terminal.test.randoop.BackendSystemRandoopTest" \
		--sourceDirs RentalApplet/src,RentalTerminal/src \
		--reportDir pitest-report \
		--outputFormats HTML,CSV \
		--threads $(or $(THREADS),1)
	@echo "Report: pitest-report/index.html"

# ============================================================
# Interactive CLIs
# ============================================================

runreception: rental-applet rental-terminal
	java -cp ${JCSIM_JAR}:RentalTerminal/bin:RentalApplet/bin terminal.reception.ReceptionTerminal

runvehicle: rental-applet rental-terminal
	java -cp ${JCSIM_JAR}:RentalTerminal/bin:RentalApplet/bin terminal.vehicle.VehicleTerminal

runsim: clean rental-applet rental-terminal
	@command -v tmux >/dev/null || { \
	  echo "tmux required. Install with: sudo apt install tmux"; exit 1; }
	@: > /tmp/rentalsim-audit.log
	@: > /tmp/rentalsim-verbose.log
	@tmux kill-session -t rentalsim 2>/dev/null; true
	tmux new-session -d -s rentalsim \
	  "java -cp ${JCSIM_JAR}:${JLINE_JAR}:RentalTerminal/bin:RentalApplet/bin terminal.simulation.SystemSimulator; read"
	tmux split-window -h -t rentalsim "bash util/runsim-tail.sh"
	tmux select-pane -t rentalsim:0.0
	tmux attach -t rentalsim

runsim-plain: clean rental-applet rental-terminal
	java -cp ${JCSIM_JAR}:${JLINE_JAR}:RentalTerminal/bin:RentalApplet/bin terminal.simulation.SystemSimulator

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
