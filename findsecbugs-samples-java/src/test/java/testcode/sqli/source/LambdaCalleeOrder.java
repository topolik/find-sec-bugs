package testcode.sqli.source;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;

/**
 * Method references whose bodies call a same-class sink, the analysis order of unrelated methods varies
 * with their names, so several variants are needed to hit the case where the enclosing method comes first.
 */
public class LambdaCalleeOrder {

    public void checkSafe1() {
        Optional.of(this).ifPresent(LambdaCalleeOrder::_helperSafe1);
    }

    private void _helperSafe1() {
        _sinkSafe1("select 1");
    }

    private void _sinkSafe1(String sql) {
        try {
            connection.prepareStatement(sql);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void checkTainted1() {
        Optional.of(this).ifPresent(LambdaCalleeOrder::_helperTainted1);
    }

    private void _helperTainted1() {
        _sinkTainted1(request.getParameter("q"));
    }

    private void _sinkTainted1(String sql) {
        try {
            connection.prepareStatement(sql);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void checkSafe2() {
        Optional.of(this).ifPresent(LambdaCalleeOrder::_helperSafe2);
    }

    private void _helperSafe2() {
        _sinkSafe2("select 1");
    }

    private void _sinkSafe2(String sql) {
        try {
            connection.prepareStatement(sql);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void checkTainted2() {
        Optional.of(this).ifPresent(LambdaCalleeOrder::_helperTainted2);
    }

    private void _helperTainted2() {
        _sinkTainted2(request.getParameter("q"));
    }

    private void _sinkTainted2(String sql) {
        try {
            connection.prepareStatement(sql);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void checkSafe3() {
        Optional.of(this).ifPresent(LambdaCalleeOrder::_helperSafe3);
    }

    private void _helperSafe3() {
        _sinkSafe3("select 1");
    }

    private void _sinkSafe3(String sql) {
        try {
            connection.prepareStatement(sql);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void checkTainted3() {
        Optional.of(this).ifPresent(LambdaCalleeOrder::_helperTainted3);
    }

    private void _helperTainted3() {
        _sinkTainted3(request.getParameter("q"));
    }

    private void _sinkTainted3(String sql) {
        try {
            connection.prepareStatement(sql);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void checkSafe4() {
        Optional.of(this).ifPresent(LambdaCalleeOrder::_helperSafe4);
    }

    private void _helperSafe4() {
        _sinkSafe4("select 1");
    }

    private void _sinkSafe4(String sql) {
        try {
            connection.prepareStatement(sql);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void checkTainted4() {
        Optional.of(this).ifPresent(LambdaCalleeOrder::_helperTainted4);
    }

    private void _helperTainted4() {
        _sinkTainted4(request.getParameter("q"));
    }

    private void _sinkTainted4(String sql) {
        try {
            connection.prepareStatement(sql);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void checkSafe5() {
        Optional.of(this).ifPresent(LambdaCalleeOrder::_helperSafe5);
    }

    private void _helperSafe5() {
        _sinkSafe5("select 1");
    }

    private void _sinkSafe5(String sql) {
        try {
            connection.prepareStatement(sql);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void checkTainted5() {
        Optional.of(this).ifPresent(LambdaCalleeOrder::_helperTainted5);
    }

    private void _helperTainted5() {
        _sinkTainted5(request.getParameter("q"));
    }

    private void _sinkTainted5(String sql) {
        try {
            connection.prepareStatement(sql);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void checkSafe6() {
        Optional.of(this).ifPresent(LambdaCalleeOrder::_helperSafe6);
    }

    private void _helperSafe6() {
        _sinkSafe6("select 1");
    }

    private void _sinkSafe6(String sql) {
        try {
            connection.prepareStatement(sql);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void checkTainted6() {
        Optional.of(this).ifPresent(LambdaCalleeOrder::_helperTainted6);
    }

    private void _helperTainted6() {
        _sinkTainted6(request.getParameter("q"));
    }

    private void _sinkTainted6(String sql) {
        try {
            connection.prepareStatement(sql);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    private Connection connection;

    private HttpServletRequest request;
}
