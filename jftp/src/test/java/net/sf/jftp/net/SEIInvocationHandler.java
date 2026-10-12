package net.sf.jftp.net;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

public class SEIInvocationHandler implements InvocationHandler {
	private Object toProxy;
	
	public SEIInvocationHandler(Object toProxy) {
		this.toProxy = toProxy;
	}

    private String getFieldNameFromMethod(Method method) {
        String methodName = method.getName();
        if (methodName.startsWith("get") || methodName.startsWith("set")) {
            return methodName.substring(3,4).toLowerCase() + methodName.substring(4);
        }
        throw new IllegalArgumentException("Method name must start with 'get' or 'set'");
    }

	@Override
	public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
		if (method.getName().startsWith("get")) {
			String fieldName = getFieldNameFromMethod(method);
			Field field = toProxy.getClass().getDeclaredField(fieldName);
			field.setAccessible(true);
			Object value = field.get(toProxy);
			return value;
			
		} else if (method.getName().startsWith("set")) {
			String fieldName = getFieldNameFromMethod(method);
			Field field = toProxy.getClass().getDeclaredField(fieldName);
			field.setAccessible(true);
			field.set(toProxy, args[0]);
			return null;
			
		} else {
			Object result = method.invoke(toProxy, args);
			return result;
		}
	}

}
