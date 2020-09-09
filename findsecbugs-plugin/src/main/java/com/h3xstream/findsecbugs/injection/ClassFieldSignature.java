/**
 * Find Security Bugs
 * Copyright (c) Philippe Arteau, All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */
package com.h3xstream.findsecbugs.injection;

import java.util.Objects;

/**
 * @author Tomas Polesovsky
 */
public class ClassFieldSignature {
    private String className;
    private String fieldName;
    private String generatedSignature;

    public ClassFieldSignature(String className, String fieldName) {
        assert className != null;
        assert fieldName != null;

        this.className = className;
        this.fieldName = fieldName;
    }

    public static ClassFieldSignature from(String fieldSignature) {
        int periodPos = fieldSignature.indexOf('.');

        String className = fieldSignature.substring(0, periodPos);
        String fieldName = fieldSignature.substring(periodPos + 1);

        return new ClassFieldSignature(className, fieldName);
    }

    public String getClassName() {
        return className;
    }

    public String getFieldName() {
        return fieldName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ClassFieldSignature that = (ClassFieldSignature) o;
        return className.equals(that.className) &&
                fieldName.equals(that.fieldName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(className, fieldName);
    }

    public String getSignature() {
        if (generatedSignature != null) {
            return generatedSignature;
        }

        generatedSignature = className + "." + fieldName;

        return generatedSignature;
    }

    @Override
    public String toString() {
        return getSignature();
    }
}
