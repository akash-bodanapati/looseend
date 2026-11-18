import java.security.MessageDigest;

public class Billing {
    public byte[] digest(String card) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5"); // expect: SEC003
        return md.digest(card.getBytes());
    }

    public void report(String card) {
        System.out.println("charging " + card); // expect: SLOP005
    }
}
