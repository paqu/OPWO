import org.gradle.api.DefaultTask;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.TaskAction;
import org.gradle.api.Project;
import java.io.File;
import java.security.MessageDigest;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.io.IOException;
import java.util.ArrayList;
import java.lang.StringBuilder;
import java.util.Date;
import java.io.BufferedWriter;
import java.io.FileWriter;

public class Metalink extends DefaultTask {
    @Input
    String fileSet;

    @Input
    String url = getProject().findProperty​("serverFilesUrl").toString();

    @Input
    String outputFile;

    private String rootDirPath;
    private ArrayList<Node> fileNodes = new ArrayList<Node>();
    BufferedWriter writer;

    @TaskAction
    public void action() throws IOException{
        File root = getProject().file( fileSet );

        this.rootDirPath = root.getAbsolutePath();

        walk(root);

        StringBuilder xml = new StringBuilder("");
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        xml.append("\n");
        xml.append("<metalink xmlns=\"urn:ietf:params:xml:ns:metalink\">");
        xml.append("\n");
        xml.append("\t<published>" + new Date() + "</published>");
        xml.append("\n");
        for (var node : fileNodes) {
            xml.append(node.toXml(url));
            xml.append("\n");
        }
        xml.append("</metalink>");

        writer = new BufferedWriter(new FileWriter(outputFile));
        writer.write(xml.toString());
        writer.close();

    }
    private void walk( File root ) {
        File[] list = root.listFiles();

        if (list == null) return;

        for ( File f : list ) {
            if ( f.isDirectory() ) {
                walk( f );
            }
            else {
                Node node = new Node(f.getAbsolutePath(),
                    f.getName(),
                    f.length(),
                    getSubDirs(rootDirPath, f.getParent()),
                    Md5Checksum(f.getAbsolutePath()));
                this.fileNodes.add(node);
            }
        }
    }

    private String getSubDirs(String root, String path) {
        return path.substring(root.length());
    }

    private String Md5Checksum(String filename) {
        MessageDigest md;
        byte[] digest;
        String checksum = "";
        try {
            md = MessageDigest.getInstance("MD5");
            md.update(Files.readAllBytes(Paths.get(filename)));
            digest = md.digest();
            checksum = bytesToHex(digest);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return checksum;
    }
    private  static String bytesToHex(byte[] bytes) {
        char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}

class Node {
    private String path;
    private String name;
    private long size;
    private String subdirs;
    private String checksum;

    public String getPath() {
        return this.path;
    }

    public String getName() {
        return this.name;
    }

    public String getSize() {
        return Long.toString(this.size);
    }

    public String getSubDirs() {
        return this.subdirs;
    }

    public String getChecksum() {
        return this.checksum;
    }
    public String toXml(String url) {
        StringBuilder xml = new StringBuilder("");
        xml.append("\t<file name=\"" + this.name + "\">");
        xml.append("\n");
        xml.append("\t\t<size>" + this.size + "</size>");
        xml.append("\n");
        xml.append("\t\t<hash type=\"md5\">" + this.checksum + "</hash>");
        xml.append("\n");
        xml.append("\t\t<url>" + url + this.subdirs + "/" + this.name + "</url>");
        xml.append("\n");
        xml.append("\t</file>");
        return xml.toString();
    }

    public Node(String path, String name, long size, String subdirs, String checksum) {
        this.path = path;
        this.name = name;
        this.size = size;
        this.subdirs = subdirs;
        this.checksum = checksum;
    }
}