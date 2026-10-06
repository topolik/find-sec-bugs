package testcode.xxe;

import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;

public class DocumentBuilderSecureFactory {

    public static DocumentBuilderFactory newDocumentBuilderFactory() {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        try {
            documentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return documentBuilderFactory;
    }

    public static Document safeSecureFactory(InputStream in) throws Exception {
        return newDocumentBuilderFactory().newDocumentBuilder().parse(in);
    }

    public static Document unsafeDefaultFactory(InputStream in) throws Exception {
        return DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(in);
    }
}
