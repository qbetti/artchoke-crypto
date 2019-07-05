package ca.uqac.lif.artichoke.examples;

import ca.uqac.lif.artichoke.Action;
import ca.uqac.lif.artichoke.ActionWrapper;
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

@SuppressWarnings("ALL")
public class HospitalScenario {

    public static final String EXAMPLE_FOLDER = "./example/";

    public static final String GROUP_DOCTOR = "doctors";
    public static final String GROUP_EMPLOYEE = "employees";
    public static final String GROUP_INSURANCE = "insurance";
    public static final String GROUP_ALL = "all";

    public static final String KR_DOCTOR = EXAMPLE_FOLDER + "kr-doctor.json";
    public static final String KR_EMPLOYEE = EXAMPLE_FOLDER + "kr-employee.json";
    public static final String KR_INSURANCE = EXAMPLE_FOLDER + "kr-insurance.json";
    public static final String KR_OWNER = EXAMPLE_FOLDER + "kr-owner.json";


    public static final String FILE_PAS = EXAMPLE_FOLDER + "owner_file.pas";




    public static final String PWD_KR_DOCTOR = "doctor";
    public static final String PWD_KR_EMPLOYEE = "employee";
    public static final String PWD_KR_INSURANCE = "insurance";
    public static final String PWD_KR_OWNER = "owner";


    public static void main(String[] args) throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException, IOException {
        Security.addProvider(new BouncyCastleProvider());

        File exampleFolder = new File(EXAMPLE_FOLDER);
        if(!exampleFolder.exists()) {
            if(!exampleFolder.mkdir()) {
                System.out.println("ERROR creating example folder, exiting.");
                System.exit(-1);
            }
        }

        byte[] doctorGroupKey = AesEncryption.generateNewKey().getEncoded();
        byte[] hospitalEmployeeGroupKey = AesEncryption.generateNewKey().getEncoded();
        byte[] insuranceGroupKey = AesEncryption.generateNewKey().getEncoded();
        byte[] superGroupKey = AesEncryption.generateNewKey().getEncoded();

        Keyring doctorKeyring = Keyring.generateNew(PWD_KR_DOCTOR, true);
        doctorKeyring.addGroup(GROUP_DOCTOR, doctorGroupKey);
        doctorKeyring.addGroup(GROUP_EMPLOYEE, hospitalEmployeeGroupKey);
        doctorKeyring.addGroup(GROUP_ALL, superGroupKey);
        doctorKeyring.saveToFile(new File(KR_DOCTOR));

        Keyring hospitalEmployeeKeyring = Keyring.generateNew(PWD_KR_EMPLOYEE, true);
        hospitalEmployeeKeyring.addGroup(GROUP_EMPLOYEE, hospitalEmployeeGroupKey);
        hospitalEmployeeKeyring.addGroup(GROUP_ALL, superGroupKey);
        hospitalEmployeeKeyring.saveToFile(new File(KR_EMPLOYEE));

        Keyring insuranceKeyring = Keyring.generateNew(PWD_KR_INSURANCE, true);
        insuranceKeyring.addGroup(GROUP_INSURANCE, insuranceGroupKey);
        insuranceKeyring.addGroup(GROUP_ALL, superGroupKey);
        insuranceKeyring.saveToFile(new File(KR_INSURANCE));

        Keyring ownerKeyring = Keyring.generateNew(PWD_KR_OWNER, true);
        ownerKeyring.addGroup(GROUP_DOCTOR, doctorGroupKey);
        ownerKeyring.addGroup(GROUP_EMPLOYEE, hospitalEmployeeGroupKey);
        ownerKeyring.addGroup(GROUP_INSURANCE, insuranceGroupKey);
        ownerKeyring.addGroup(GROUP_ALL, superGroupKey);
        ownerKeyring.saveToFile(new File(KR_OWNER));


        Action action0 = new Action("first_name", "write", "Quentin");
        Action action1 = new Action("last_name", "write", "Betti");
        Action action2 = new Action("insurance_nb", "write", "45451AE4C");
        Action action3 = new Action("date_of_birth", "write", "16/09/1992");
        Action action4 = new Action("document", "sign", "NULL");

        Action action5 = new Action("tests", "add", "body temperature: 39°C");
        Action action6 = new Action("symptoms", "add", "fever");
        Action action7 = new Action("symptoms", "add", "weakness");
        Action action8 = new Action("symptoms/1", "update", "light weakness");

        Action action9 = new Action("pathology", "add", "flu");
        Action action10 = new Action("prescription", "add", "3 200mg ibuprofen pills per day");

        Action action11 = new Action("prescription/0/reimbursement", "write", "$25.50");

        Peer owner = new Peer("Quentin Betti", ownerKeyring.getHexPublicKey());
        Peer doctor = new Peer("Dr. Grey",  doctorKeyring.getHexPublicKey());
        Peer employee = new Peer("Mrs. Nurse", hospitalEmployeeKeyring.getHexPublicKey());
        Peer insurance = new Peer("M. Desjardins", insuranceKeyring.getHexPublicKey());

        History history = new History();

        history.add(action0, owner, GROUP_ALL, ownerKeyring);
        history.add(action1, owner, GROUP_ALL, ownerKeyring);
        history.add(action2, owner, GROUP_ALL, ownerKeyring);
        history.add(action3, owner, GROUP_ALL, ownerKeyring);
        history.add(action4, owner, GROUP_ALL, ownerKeyring);

        history.add(action5, employee, GROUP_EMPLOYEE, hospitalEmployeeKeyring);
        history.add(action6, employee, GROUP_EMPLOYEE, hospitalEmployeeKeyring);
        history.add(action7, employee, GROUP_EMPLOYEE, hospitalEmployeeKeyring);
        history.add(action8, employee, GROUP_EMPLOYEE, hospitalEmployeeKeyring);

        history.add(action9, doctor, GROUP_ALL, doctorKeyring);
        history.add(action10, doctor, GROUP_ALL, doctorKeyring);

        history.add(action11, insurance, GROUP_INSURANCE, insuranceKeyring);

        FileWriter writer = new FileWriter(FILE_PAS);
        writer.write(history.encode());
        writer.close();

        Scanner scanner = new Scanner(new File(FILE_PAS));
        String encodedHistory = scanner.nextLine();
        scanner.close();

        History decodedHistory = History.decode(encodedHistory);
        System.out.println("Number of violations: " + decodedHistory.verify().size());

        System.out.println("\nFor owner");
        List<ActionWrapper> actionWrappers = decodedHistory.decrypt(ownerKeyring);
        for(ActionWrapper actionWrapper : actionWrappers) {
            System.out.println(actionWrapper);
        }

        System.out.println("\nFor doctor");
        actionWrappers = decodedHistory.decrypt(doctorKeyring);
        for(ActionWrapper actionWrapper : actionWrappers) {
            System.out.println(actionWrapper);
        }

        System.out.println("\nFor nurse");
        actionWrappers = decodedHistory.decrypt(hospitalEmployeeKeyring);
        for(ActionWrapper actionWrapper : actionWrappers) {
            System.out.println(actionWrapper);
        }

        System.out.println("\nFor insurance");
        actionWrappers = decodedHistory.decrypt(insuranceKeyring);
        for(ActionWrapper actionWrapper : actionWrappers) {
            System.out.println(actionWrapper);
        }
    }
}
