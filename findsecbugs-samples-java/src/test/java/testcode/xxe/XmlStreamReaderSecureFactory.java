package testcode.xxe;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import java.io.InputStream;

public class XmlStreamReaderSecureFactory {

    public static XMLInputFactory newXMLInputFactory() {
        XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);
        return xmlInputFactory;
    }

    public static XMLStreamReader safeSecureFactory(InputStream in) throws Exception {
        XMLInputFactory xmlInputFactory = newXMLInputFactory();
        return xmlInputFactory.createXMLStreamReader(in);
    }

    public static XMLStreamReader unsafeDefaultFactory(InputStream in) throws Exception {
        XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
        return xmlInputFactory.createXMLStreamReader(in);
    }
}
