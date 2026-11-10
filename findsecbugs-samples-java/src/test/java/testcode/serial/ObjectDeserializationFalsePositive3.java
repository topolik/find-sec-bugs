package testcode.serial;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * Like readObject in ObjectDeserializationFalsePositive1, readExternal only fetches the next object of a stream whose
 * deserialization was started elsewhere.
 */
public class ObjectDeserializationFalsePositive3 implements Externalizable {
    Object param;

    @Override
    public void readExternal(ObjectInput objectInput) throws IOException, ClassNotFoundException {
        param = objectInput.readObject();
    }

    @Override
    public void writeExternal(ObjectOutput objectOutput) throws IOException {
        objectOutput.writeObject(param);
    }
}
