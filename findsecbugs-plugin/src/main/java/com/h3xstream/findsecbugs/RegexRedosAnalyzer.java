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
package com.h3xstream.findsecbugs;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

public class RegexRedosAnalyzer {

    private static final char[] OPENING_CHAR = {'(', '['};

    private static final char[] CLOSING_CHAR = {')', ']'};

    private static final char[] PLUS_CHAR = {'+', '*', '?'};

    private boolean vulnerable = false;


    public boolean isVulnerable() {
        return vulnerable;
    }

    public void analyseRegexString(String regex) {
        if (regex.length() > 0) {
            recurAnalyseRegex(regex, regex.length() - 1, 0);
        }
    }

    private int recurAnalyseRegex(String regex, int startPosition, int level) {
//        print(level, "level = " + level);
        if (level == 2) {
            vulnerable = true;

            return 0;
        }


//        print(level, "Analysing " + regex.substring(0, startPosition + 1));

        boolean openingMode = false;

        for (int i = startPosition; i >= 0; i--) {
//            print(level, "[" + i + "] = '" + regex.charAt(i) + "'");

            if (isChar(regex, i, OPENING_CHAR)) {
//                print(level, "<<<<");
                return i;
            }

            if (isChar(regex, i, CLOSING_CHAR)) {
                int newLevel = level;
                if (i + 1 < regex.length() && isChar(regex, i + 1, PLUS_CHAR) && !isDelimitedRun(regex, i) &&
                        !isSeparatedGroup(regex, i, level)) {
                    newLevel += 1;
                }
//                print(level, ">>>>");
                openingMode = true;
                i = recurAnalyseRegex(regex, i - 1, newLevel);
                if (i == -1) {
                    return 0;
                }
//                print(level, "Restarting at " + i);
            }
        }

//        print(level, "END!");

        return 0;
    }

    /**
     * A run such as '[^']*' stops only at its delimiter, so it can match a given input in one way only.
     */
    private boolean isDelimitedRun(String regex, int closingPosition) {
        if (closingPosition < 3 || closingPosition + 2 >= regex.length()) {
            return false;
        }
        char delimiter = regex.charAt(closingPosition - 1);
        return regex.charAt(closingPosition) == ']' && regex.charAt(closingPosition - 2) == '^' &&
                isChar(regex, closingPosition - 3, OPENING_CHAR) && delimiter != '\\' &&
                regex.charAt(closingPosition + 2) == delimiter;
    }

    /**
     * A group such as (\.[a-z]+)* starts each repetition with a separator that nothing else in the group matches, so it
     * can match a given input in one way only. Inside another repetition it still adds a nesting level.
     */
    private boolean isSeparatedGroup(String regex, int closingPosition, int level) {
        if (level != 0 || regex.charAt(closingPosition) != ')') {
            return false;
        }
        int position = findOpeningParenthesis(regex, closingPosition);
        if (position < 0) {
            return false;
        }
        position++;
        if (regex.startsWith("?:", position)) {
            position += 2;
        } else if (position < closingPosition && regex.charAt(position) == '?') {
            return false;
        }
        List<boolean[]> charSets = new ArrayList<boolean[]>();
        while (position < closingPosition) {
            boolean[] charSet = new boolean[128];
            position = parseCharSet(regex, position, charSet);
            if (position < 0) {
                return false;
            }
            if (charSets.isEmpty() && position < closingPosition && isChar(regex, position, PLUS_CHAR)) {
                return false;
            }
            charSets.add(charSet);
            while (position < closingPosition && isChar(regex, position, PLUS_CHAR)) {
                position++;
            }
        }
        if (charSets.size() < 2) {
            return false;
        }
        boolean[] separator = charSets.get(0);
        for (boolean[] charSet : charSets.subList(1, charSets.size())) {
            for (int c = 0; c < 128; c++) {
                if (separator[c] && charSet[c]) {
                    return false;
                }
            }
        }
        return true;
    }

    private int findOpeningParenthesis(String regex, int closingPosition) {
        Deque<Integer> openings = new ArrayDeque<Integer>();
        boolean inClass = false;
        for (int i = 0; i < closingPosition; i++) {
            char c = regex.charAt(i);
            if (c == '\\') {
                i++;
            } else if (inClass) {
                inClass = c != ']';
            } else if (c == '[') {
                inClass = true;
            } else if (c == '(') {
                openings.push(i);
            } else if (c == ')' && !openings.isEmpty()) {
                openings.pop();
            }
        }
        return openings.isEmpty() ? -1 : openings.peek();
    }

    /**
     * Reads a literal, an escaped symbol or a simple character class into charSet.
     *
     * @return the position after it, or -1 when it is anything else
     */
    private int parseCharSet(String regex, int position, boolean[] charSet) {
        char c = regex.charAt(position);
        if (c == '\\') {
            return addLiteral(regex, position + 1, charSet);
        }
        if (c != '[') {
            return "()|.^${}+*?".indexOf(c) >= 0 ? -1 : addLiteral(regex, position, charSet);
        }
        position++;
        if (position >= regex.length() || regex.charAt(position) == '^') {
            return -1;
        }
        while (position < regex.length() && regex.charAt(position) != ']') {
            boolean escaped = regex.charAt(position) == '\\';
            if (escaped) {
                position++;
            }
            if (position >= regex.length() || (escaped && Character.isLetterOrDigit(regex.charAt(position))) ||
                    regex.charAt(position) >= 128 || (!escaped && regex.charAt(position) == '[')) {
                return -1;
            }
            char first = regex.charAt(position);
            char last = first;
            if (position + 2 < regex.length() && regex.charAt(position + 1) == '-' &&
                    regex.charAt(position + 2) != ']') {
                last = regex.charAt(position + 2);
                if (last == '\\' || last >= 128 || last < first) {
                    return -1;
                }
                position += 2;
            }
            for (char member = first; member <= last; member++) {
                charSet[member] = true;
            }
            position++;
        }
        return position < regex.length() ? position + 1 : -1;
    }

    private int addLiteral(String regex, int position, boolean[] charSet) {
        if (position >= regex.length()) {
            return -1;
        }
        char c = regex.charAt(position);
        if (c >= 128 || (regex.charAt(position - 1) == '\\' && Character.isLetterOrDigit(c))) {
            return -1;
        }
        charSet[c] = true;
        return position + 1;
    }

    /**
     * @param value
     * @param position
     * @param charToTest
     * @return
     */
    private boolean isChar(String value, int position, char[] charToTest) {
        char actualChar = value.charAt(position);
        boolean oneCharFound = false;
        for (char ch : charToTest) {
            if (actualChar == ch) {
                oneCharFound = true;
                break;
            }
        }
        return oneCharFound && (position == 0 || value.charAt(position - 1) != '\\');
    }

    //Debug method

//    private void print(int level,Object obj) {
//        System.out.println(lvl(level) + "> "+ obj);
//    }
//
//    private String lvl(int level) {
//        StringBuilder str = new StringBuilder();
//        for(int i=0;i<level;i++) {
//            str.append("-\t");
//        }
//        return str.toString();
//    }
}
