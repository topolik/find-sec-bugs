# Jakarta Migration Plan

## Goal
Replace the runtime `JakartaPackageAliasing` approach with explicit build-time jakarta entries
in txt config files, matching the `jakarta-migration` branch style. Also adopt higher test
coverage from that branch: new stubs, new test code, more detector tests.

## Strategy
- Remove `JakartaPackageAliasing.java` and all references to it
- Add jakarta entries explicitly to each config/sink txt file (mirrors the javax entries)
- Add new sample dep stubs for jakarta.el, jakarta.faces, jakarta.mail
- Extend test code with richer jakarta sample classes
- Add detector tests for each new jakarta category
- The `jakarta-transform.sh` script is a reference (not a build artifact; not run in CI)
- Keep `BaseConfigValidation.java` skip for jakarta classes (stubs not always on classpath)

---

## Phase 1: Remove runtime approach

### 1.1 Delete JakartaPackageAliasing.java
- `findsecbugs-plugin/src/main/java/com/h3xstream/findsecbugs/taintanalysis/JakartaPackageAliasing.java`
  → delete

### 1.2 Revert SinksLoader.java
- Remove `import com.h3xstream.findsecbugs.taintanalysis.JakartaPackageAliasing;`
- Remove the `JakartaPackageAliasing.toJakarta()` call and surrounding if-block from `loadSinks()`

### 1.3 Revert TaintConfigLoader.java
- Remove the `JakartaPackageAliasing.toJakarta()` call and surrounding if-block from `load()`

### 1.4 Restore path-traversal-in.txt
- Re-add the `jakarta/activation/FileDataSource.<init>(Ljava/lang/String;)V:0` line
  (our working tree removed it but master already has it)

---

## Phase 2: Add jakarta entries to config txt files

Each section lists the lines to append (taken from jakarta-migration, deduped against master).

### 2.1 injection-sinks/el.txt
Append:
```
jakarta/el/ExpressionFactory.createValueExpression(Ljakarta/el/ELContext;Ljava/lang/String;Ljava/lang/Class;)Ljakarta/el/ValueExpression;:1
jakarta/el/ExpressionFactory.createMethodExpression(Ljakarta/el/ELContext;Ljava/lang/String;Ljava/lang/Class;[Ljava/lang/Class;)Ljakarta/el/MethodExpression;:2
```

### 2.2 injection-sinks/requestdispatcher-file-disclosure.txt
Append:
```
jakarta/servlet/RequestDispatcher.forward(Ljakarta/servlet/ServletRequest;Ljakarta/servlet/ServletResponse;)V:2
jakarta/servlet/RequestDispatcher.include(Ljakarta/servlet/ServletRequest;Ljakarta/servlet/ServletResponse;)V:2
```
Note: master only has the javax include line; jakarta-migration also added the javax include (already present).

### 2.3 injection-sinks/response-splitting.txt
Append:
```
jakarta/servlet/http/Cookie.<init>(Ljava/lang/String;Ljava/lang/String;)V:0,1
jakarta/servlet/http/Cookie.setValue(Ljava/lang/String;)V:0
jakarta/servlet/http/HttpServletResponse.addHeader(Ljava/lang/String;Ljava/lang/String;)V:0,1
jakarta/servlet/http/HttpServletResponse.setHeader(Ljava/lang/String;Ljava/lang/String;)V:0,1
jakarta/servlet/http/HttpServletResponseWrapper.addHeader(Ljava/lang/String;Ljava/lang/String;)V:0,1
jakarta/servlet/http/HttpServletResponseWrapper.setHeader(Ljava/lang/String;Ljava/lang/String;)V:0,1
```

### 2.4 injection-sinks/smtp.txt
Append (jakarta-migration also added javax/mail/Message.setDisposition which is already in master):
```
jakarta/mail/Message.setSubject(Ljava/lang/String;)V:0
jakarta/mail/Message.addHeader(Ljava/lang/String;Ljava/lang/String;)V:0,1
jakarta/mail/Message.setDescription(Ljava/lang/String;)V:0
jakarta/mail/Message.setDisposition(Ljava/lang/String;)V:0
```

### 2.5 injection-sinks/sql-jpa.txt
Append:
```
jakarta/persistence/EntityManager.createQuery(Ljava/lang/String;)Ljakarta/persistence/Query;:0
jakarta/persistence/EntityManager.createQuery(Ljava/lang/String;Ljava/lang/Class;)Ljakarta/persistence/TypedQuery;:1
jakarta/persistence/EntityManager.createNativeQuery(Ljava/lang/String;)Ljakarta/persistence/Query;:0
jakarta/persistence/EntityManager.createNativeQuery(Ljava/lang/String;Ljava/lang/String;)Ljakarta/persistence/Query;:1
jakarta/persistence/EntityManager.createNativeQuery(Ljava/lang/String;Ljava/lang/Class;)Ljakarta/persistence/Query;:1
```

### 2.6 injection-sinks/trust-boundary-violation-attribute.txt
Append:
```
jakarta/servlet/http/HttpSession.setAttribute(Ljava/lang/String;Ljava/lang/Object;)V:1
jakarta/servlet/http/HttpSession.putValue(Ljava/lang/String;Ljava/lang/Object;)V:1
```
Note: jakarta-migration also added `javax/servlet/http/HttpSession.putValue` — master does NOT have it, so add it to javax block too.

### 2.7 injection-sinks/trust-boundary-violation-value.txt
Append:
```
jakarta/servlet/http/HttpSession.setAttribute(Ljava/lang/String;Ljava/lang/Object;)V:0
jakarta/servlet/http/HttpSession.putValue(Ljava/lang/String;Ljava/lang/Object;)V:0
```
Same note: also add `javax/servlet/http/HttpSession.putValue(...):0` for the javax block.

### 2.8 injection-sinks/xss-jsp.txt
Append after existing javax entries:
```
- Sinks from jakarta.servlet.jsp.JspWriter
jakarta/servlet/jsp/JspWriter.write(Ljava/lang/String;)V:0
jakarta/servlet/jsp/JspWriter.write(Ljava/lang/String;II)V:2
jakarta/servlet/jsp/JspWriter.write([C)V:0
jakarta/servlet/jsp/JspWriter.write([CII)V:2
jakarta/servlet/jsp/JspWriter.append(Ljava/lang/CharSequence;)Ljava/io/PrintWriter;:0
jakarta/servlet/jsp/JspWriter.append(Ljava/lang/CharSequence;II)Ljava/io/PrintWriter;:2
jakarta/servlet/jsp/JspWriter.append(C)Ljava/io/PrintWriter;:0
jakarta/servlet/jsp/JspWriter.print([C)V:0
jakarta/servlet/jsp/JspWriter.print(Ljava/lang/String;)V:0
jakarta/servlet/jsp/JspWriter.print(Ljava/lang/Object;)V:0
jakarta/servlet/jsp/JspWriter.print(C)V:0
jakarta/servlet/jsp/JspWriter.println([C)V:0
jakarta/servlet/jsp/JspWriter.println(Ljava/lang/String;)V:0
jakarta/servlet/jsp/JspWriter.println(Ljava/lang/Object;)V:0
jakarta/servlet/jsp/JspWriter.println(C)V:0
```

### 2.9 injection-sinks/xss-servlet.txt
Append:
```
jakarta/servlet/http/HttpServletResponse.sendError(ILjava/lang/String;)V:0
jakarta/servlet/http/HttpServletResponse.setStatus(ILjava/lang/String;)V:0
jakarta/servlet/http/HttpServletResponseWrapper.sendError(ILjava/lang/String;)V:0
jakarta/servlet/http/HttpServletResponseWrapper.setStatus(ILjava/lang/String;)V:0
jakarta/servlet/ServletOutputStream.print(Ljava/lang/String;)V:0
jakarta/servlet/ServletOutputStream.println(Ljava/lang/String;)V:0
```
Note: jakarta-migration also added `javax/servlet/ServletOutputStream.println` — check master.

### 2.10 safe-encoders/other.txt
Append:
```
jakarta/xml/bind/DatatypeConverter.printHexBinary([B)Ljava/lang/String;:SAFE
```

### 2.11 taint-config/dropwizard.txt
Append:
```
io/dropwizard/servlets/Servlets.getFullUrl(Ljakarta/servlet/http/HttpServletRequest;)Ljava/lang/String;:TAINTED
```

### 2.12 taint-config/java-ee.txt
Append all the jakarta/servlet/ServletRequest and jakarta/servlet/http/HttpServletRequest entries
from jakarta-migration (36 lines). Also add:
```
jakarta/ws/rs/core/MultivaluedMap.getFirst(Ljava/lang/Object;)Ljava/lang/Object;:TAINTED
jakarta/servlet/jsp/JspWriter.write([C)V:UNKNOWN
jakarta/servlet/jsp/JspWriter.write([CII)V:UNKNOWN
jakarta/servlet/jsp/JspWriter.print([C)V:UNKNOWN
jakarta/servlet/jsp/JspWriter.print(Ljava/lang/Object;)V:UNKNOWN
jakarta/servlet/jsp/JspWriter.println([C)V:UNKNOWN
```

### 2.13 taint-config/portlet.txt
Append all the jakarta/portlet entries from jakarta-migration (44 lines).

### 2.14 taint-config/taint-param-annotations.txt
Current working tree already added jakarta ws.rs entries. Rebase this to match the
jakarta-migration format exactly (including the added javax/ws/rs/QueryParam line fix).

### 2.15 taint-config/wicket.txt
Append:
```
org/apache/wicket/protocol/http/servlet/ServletPartFileItem.getFileName(Ljakarta/servlet/http/Part;)Ljava/lang/String;:TAINTED
```

### 2.16 test/resources/xss/CustomConfig.txt
Append:
```
jakarta/servlet/http/HttpServletRequest.getAttribute("safe"):SAFE@org/apache/jsp/xss/xss_005f8_005frequest_005fattribute_jsp
jakarta/servlet/http/HttpServletRequest.getAttribute("tainted"):TAINTED@org/apache/jsp/xss/xss_005f8_005frequest_005fattribute_jsp
jakarta/servlet/http/HttpSession.getAttribute(UNKNOWN):SAFE@org/apache/jsp/xss/xss_005f8_005frequest_005fattribute_jsp
```

---

## Phase 3: Add new stubs to findsecbugs-samples-deps

New files to create (all from jakarta-migration content):

### 3.1 jakarta.activation
- `jakarta/activation/FileDataSource.java`

### 3.2 jakarta.el
- `jakarta/el/ELContext.java`
- `jakarta/el/ExpressionFactory.java`
- `jakarta/el/MethodExpression.java`
- `jakarta/el/ValueExpression.java`

### 3.3 jakarta.faces
- `jakarta/faces/application/Application.java`
- `jakarta/faces/context/FacesContext.java`

### 3.4 jakarta.mail
- `jakarta/mail/Address.java`
- `jakarta/mail/Authenticator.java`
- `jakarta/mail/Message.java`
- `jakarta/mail/MessagingException.java`
- `jakarta/mail/Part.java`
- `jakarta/mail/PasswordAuthentication.java`
- `jakarta/mail/Service.java`
- `jakarta/mail/Session.java`
- `jakarta/mail/Transport.java`
- `jakarta/mail/internet/AddressException.java`
- `jakarta/mail/internet/InternetAddress.java`
- `jakarta/mail/internet/MimeMessage.java`

### 3.5 jakarta.persistence (already exist — EntityManager, Query, TypedQuery)
No action needed.

### 3.6 jakarta.servlet additions
- `jakarta/servlet/http/HttpServletResponseWrapper.java`
- `jakarta/servlet/jsp/JspWriter.java` — create a proper stub (not "TBD" file)
  (jakarta-migration has `JspWriterJakartaTBD.java` but the sink config uses `JspWriter`)

---

## Phase 4: Add and extend test sample code

### 4.1 Extend JakartaUnvalidatedRedirectServlet.java (already exists, needs enrichment)
Add `unvalidatedRedirect2` (uses addHeader), `falsePositiveRedirect1`, `falsePositiveRedirect2`
matching the jakarta-migration version.

### 4.2 Update ResponseSplittingServlet.java
Add the `JakartaResponseSplittingServlet` inner static class (uses jakarta.servlet.http.*).

### 4.3 Add JakartaElExpressionSample.java
New file: `findsecbugs-samples-java/src/test/java/testcode/script/JakartaElExpressionSample.java`

### 4.4 Add JakartaSmtpClient.java
New file: `findsecbugs-samples-java/src/test/java/testcode/smtp/JakartaSmtpClient.java`

### 4.5 Extend JpaSql.java
Add `JakartaJpaSql` inner static class using `jakarta.persistence.*`.

---

## Phase 5: Add and extend detector tests

### 5.1 UnvalidatedRedirectDetectorTest.java (already modified)
Extend `detectJakartaUnvalidatedRedirect()` to also verify `unvalidatedRedirect2` at Medium
and assert `times(2)` total — matching jakarta-migration.

### 5.2 HttpResponseSplittingDetectorTest.java
Add `detectJakartaResponseSplitting()` test verifying the new inner class, matching
jakarta-migration exactly (8 bugs: 2 Low + 6 Medium).

### 5.3 ElInjectionTest.java
Add `detectInjectionJakarta()` test verifying `JakartaElExpressionSample`.

### 5.4 SmtpHeaderInjectionDetectorTest.java
Add `detectJakartaSmtpInjection()` test verifying `JakartaSmtpClient`.

### 5.5 JpaInjectionSourceTest.java
Add `detectJakartaJpaInjection()` and `detectJakartaJpaInjectionInNativeQuery()` tests.

---

## Execution order
1. Phase 1 (revert runtime approach)
2. Phase 2 (update txt files)
3. Phase 3 (add stubs)
4. Phase 4 (extend test sample code)
5. Phase 5 (add detector tests)
6. Build and run tests to validate

## Notes
- The `jakarta-transform.sh` in the root is a developer utility for auditing/regenerating
  jakarta entries; it is not run in CI.
- `BaseConfigValidation.java` change (skip jakarta.*) is kept because not all jakarta stubs
  are resolvable at test classpath validation time.
- Line format in txt files: keep the same style as existing javax entries (same file, same
  block grouping pattern).
