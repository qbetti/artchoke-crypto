package ca.uqac.lif.artichoke.examples;

import ca.uqac.lif.artichoke.Action;
import ca.uqac.lif.artichoke.WrappedAction;
import ca.uqac.lif.artichoke.History;
import ca.uqac.lif.artichoke.Peer;
import ca.uqac.lif.artichoke.crypto.AesEncryption;
import ca.uqac.lif.artichoke.exceptions.BadPassphraseException;
import ca.uqac.lif.artichoke.exceptions.GroupIdException;
import ca.uqac.lif.artichoke.exceptions.PrivateKeyDecryptionException;
import ca.uqac.lif.artichoke.keyring.Keyring;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Security;
import java.util.List;
import java.util.Scanner;

/**
 * The class depicts a use case scenario for keyring and artichoke.
 * In this scenario, a patient is admitted to an hospital where he will
 * pass a serie of tests and will receive corresponding prescription that may be or not
 * reimbursed by its insurance. These piece of information are stored in the metadata
 * of a file using the secure format of the peer-action sequences.
 */
public class HospitalScenario {

    /**
     * The folder that will contained all the generated files
     */
    public static final String EXAMPLE_FOLDER = "./example/";

    /**
     * Names of the different groups for this scenario
     */
    public static final String GROUP_DOCTOR = "doctors";
    public static final String GROUP_EMPLOYEE = "employees";
    public static final String GROUP_INSURANCE = "insurance";
    public static final String GROUP_ALL = "all";

    /**
     * Names for the keyring files
     */
    public static final String KR_DOCTOR = EXAMPLE_FOLDER + "kr-doctor.json";
    public static final String KR_EMPLOYEE = EXAMPLE_FOLDER + "kr-employee.json";
    public static final String KR_INSURANCE = EXAMPLE_FOLDER + "kr-insurance.json";
    public static final String KR_PATIENT = EXAMPLE_FOLDER + "kr-patient.json";

    /**
     * The passwords for the keyring files
     */
    public static final String PWD_KR_DOCTOR = "doctor";
    public static final String PWD_KR_NURSE = "nurse";
    public static final String PWD_KR_INSURANCE = "insurance";
    public static final String PWD_KR_PATIENT = "patient";

    /**
     * The name of the file that will contain the metadata
     */
    public static final String FILE_PAS = EXAMPLE_FOLDER + "patient_file.pas";


    public static void main(String[] args) throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException, IOException {
        // Needed for encryption/decryption purposes
        Security.addProvider(new BouncyCastleProvider());

        // Checking and creating this example folder
        File exampleFolder = new File(EXAMPLE_FOLDER);
        if(!exampleFolder.exists()) {
            if(!exampleFolder.mkdir()) {
                System.out.println("ERROR creating example folder, exiting.");
                System.exit(-1);
            }
        }

        // Generating all the group keys
        byte[] doctorGroupKey = AesEncryption.generateNewKey().getEncoded();
        byte[] hospitalEmployeeGroupKey = AesEncryption.generateNewKey().getEncoded();
        byte[] insuranceGroupKey = AesEncryption.generateNewKey().getEncoded();
        byte[] superGroupKey = AesEncryption.generateNewKey().getEncoded();

        // Generating the doctor's keyring file
        Keyring doctorKeyring = Keyring.generateNew(PWD_KR_DOCTOR, true);
        doctorKeyring.addGroup(GROUP_DOCTOR, doctorGroupKey);
        doctorKeyring.addGroup(GROUP_EMPLOYEE, hospitalEmployeeGroupKey);
        doctorKeyring.addGroup(GROUP_ALL, superGroupKey);
        doctorKeyring.saveToFile(new File(KR_DOCTOR));

        // Generating the nurse's keyring file
        Keyring nurseKeyring = Keyring.generateNew(PWD_KR_NURSE, true);
        nurseKeyring.addGroup(GROUP_EMPLOYEE, hospitalEmployeeGroupKey);
        nurseKeyring.addGroup(GROUP_ALL, superGroupKey);
        nurseKeyring.saveToFile(new File(KR_EMPLOYEE));

        // Generating the insurance employee's keyring file
        Keyring insuranceKeyring = Keyring.generateNew(PWD_KR_INSURANCE, true);
        insuranceKeyring.addGroup(GROUP_INSURANCE, insuranceGroupKey);
        insuranceKeyring.addGroup(GROUP_ALL, superGroupKey);
        insuranceKeyring.saveToFile(new File(KR_INSURANCE));

        // Generating the patient's keyring file
        Keyring ownerKeyring = Keyring.generateNew(PWD_KR_PATIENT, true);
        ownerKeyring.addGroup(GROUP_DOCTOR, doctorGroupKey);
        ownerKeyring.addGroup(GROUP_EMPLOYEE, hospitalEmployeeGroupKey);
        ownerKeyring.addGroup(GROUP_INSURANCE, insuranceGroupKey);
        ownerKeyring.addGroup(GROUP_ALL, superGroupKey);
        ownerKeyring.saveToFile(new File(KR_PATIENT));


        // Creating actions that will appended to the peer-action sequence

        // The patient is adding is own personal info and sign the document
        Action action0 = new Action("first_name", "write", "Quentin");
        Action action1 = new Action("last_name", "write", "Betti");
        Action action2 = new Action("insurance_nb", "write", "45451AE4C");
        Action action3 = new Action("date_of_birth", "write", "16/09/1992");
        Action action4 = new Action("document", "sign", "NULL");

        // The nurse conducts a bunch of tests
        Action action5 = new Action("tests", "add", "body temperature: 39°C");
        Action action6 = new Action("symptoms", "add", "fever");
        Action action7 = new Action("symptoms", "add", "weakness");
        Action action8 = new Action("symptoms/1", "update", "light weakness");

        // The doctor goes through the result of the tests, deducts an pathology and prescribe some drugs
        Action action9 = new Action("pathology", "add", "flu");
        Action action10 = new Action("prescription", "add", "3 200mg ibuprofen pills per day");

        // The insurance sees the prescribed pills and fills in the reimbursed amount for this treatment
        Action action11 = new Action("prescription/0/reimbursement", "write", "$25.50");

        Peer patient = new Peer("Quentin Betti", ownerKeyring.getHexPublicKey());
        Peer doctor = new Peer("Dr. Grey",  doctorKeyring.getHexPublicKey());
        Peer employee = new Peer("Mrs. Nurse", nurseKeyring.getHexPublicKey());
        Peer insurance = new Peer("M. Desjardins", insuranceKeyring.getHexPublicKey());


        // Creating a new peer-action sequence and appending the actions
        History history = new History();

        history.add(action0, patient, GROUP_ALL, ownerKeyring);
        history.add(action1, patient, GROUP_ALL, ownerKeyring);
        history.add(action2, patient, GROUP_ALL, ownerKeyring);
        history.add(action3, patient, GROUP_ALL, ownerKeyring);
        history.add(action4, patient, GROUP_ALL, ownerKeyring);

        history.add(action5, employee, GROUP_EMPLOYEE, nurseKeyring);
        history.add(action6, employee, GROUP_EMPLOYEE, nurseKeyring);
        history.add(action7, employee, GROUP_EMPLOYEE, nurseKeyring);
        history.add(action8, employee, GROUP_EMPLOYEE, nurseKeyring);

        history.add(action9, doctor, GROUP_ALL, doctorKeyring);
        history.add(action10, doctor, GROUP_ALL, doctorKeyring);

        history.add(action11, insurance, GROUP_INSURANCE, insuranceKeyring);

        // Writing the history in a file
        FileWriter writer = new FileWriter(FILE_PAS);
        writer.write(history.encode());
        writer.close();

        // Retrieving the history and verifying its integrity by listing the potential violation
        Scanner scanner = new Scanner(new File(FILE_PAS));
        String encodedHistory = scanner.nextLine();
        scanner.close();
        History decodedHistory = History.decode(encodedHistory);
        System.out.println("Number of violations: " + decodedHistory.verify().size());

        // Listing all the actions from each peer's point of view
        System.out.println("\nFor patient");
        List<WrappedAction> wrappedActions = decodedHistory.decrypt(ownerKeyring);
        for(WrappedAction wrappedAction : wrappedActions) {
            System.out.println(wrappedAction);
        }

        System.out.println("\nFor doctor");
        wrappedActions = decodedHistory.decrypt(doctorKeyring);
        for(WrappedAction wrappedAction : wrappedActions) {
            System.out.println(wrappedAction);
        }

        System.out.println("\nFor nurse");
        wrappedActions = decodedHistory.decrypt(nurseKeyring);
        for(WrappedAction wrappedAction : wrappedActions) {
            System.out.println(wrappedAction);
        }

        System.out.println("\nFor insurance");
        wrappedActions = decodedHistory.decrypt(insuranceKeyring);
        for(WrappedAction wrappedAction : wrappedActions) {
            System.out.println(wrappedAction);
        }
    }
}
