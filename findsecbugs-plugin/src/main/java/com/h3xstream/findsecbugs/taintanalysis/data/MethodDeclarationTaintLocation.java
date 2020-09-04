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
package com.h3xstream.findsecbugs.taintanalysis.data;

import edu.umd.cs.findbugs.classfile.MethodDescriptor;

/**
 * Specification of a taint source location where the source is method declaration
 * 
 * @author Tomas Polesovsky (Liferay Inc.)
 */
public class MethodDeclarationTaintLocation extends TaintLocation {

    public MethodDeclarationTaintLocation(MethodDescriptor methodDescriptor) {
        super(methodDescriptor, 0);
    }
}
