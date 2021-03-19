package dmit2015.security;

import javax.inject.Inject;
import javax.interceptor.AroundInvoke;
import javax.interceptor.InvocationContext;
import javax.security.enterprise.SecurityContext;
import java.util.Locale;
import java.util.logging.Logger;

public class MovieSecurityInterceptor {

    @Inject
    private Logger _logger;

    @Inject
    private SecurityContext _securityContext;

    @AroundInvoke
    public Object verifyAccess(InvocationContext ic) throws Exception {
        String methodName = ic.getMethod().getName();
        _logger.info("Entering method " + methodName);
        // Only authenticated users with the role USER or Sales can execute the update or add method
        // Only authenticated users with the role ADMIN or Executive or Adminstration can execute the delete method
        if (_securityContext.getCallerPrincipal() == null) {
            throw new RuntimeException("Access denied!. Only authenticated users have permission to execute this method.");
        }
        if (methodName.toLowerCase().startsWith("add") || methodName.toLowerCase().startsWith("update")) {
            if (!_securityContext.isCallerInRole("USER") && !_securityContext.isCallerInRole("Sales")) {
                throw new RuntimeException("Access denied!. You do not have permission to execute this method.");
            }
        }
        if (methodName.toLowerCase().startsWith("remove") ) {
            if (!_securityContext.isCallerInRole("ADMIN")
                    && !_securityContext.isCallerInRole("Executive")
                    && !_securityContext.isCallerInRole("Administration")) {
                throw new RuntimeException("Access denied!. You do not have permission to execute this method.");
            }
        }

        return ic.proceed();
    }
}
