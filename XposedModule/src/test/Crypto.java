package test;

import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;

import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Member;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.HashMap;
import java.util.Map;

import android.annotation.SuppressLint;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_InitPackageResources.Unhook;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class Crypto implements IXposedHookLoadPackage {
	@SuppressLint("UseSparseArrays")
	static Map<Integer, Streams> keys = new HashMap<Integer, Streams>();
	XC_MethodHook.Unhook uIs;
	XC_MethodHook.Unhook uOs;

	public void handleLoadPackage(final LoadPackageParam lpparam)
			throws Throwable {
		if (!lpparam.packageName.equals("com.example.androidclient"))
			return;

		/* debugging */
		XposedBridge.log("androidclient package");
				
		findAndHookMethod("java.net.Socket", lpparam.classLoader, "connect",
			SocketAddress.class, new XC_MethodHook() {
			@Override
			protected void afterHookedMethod(MethodHookParam param)
					throws Throwable {	
				
				if (uIs != null) {
					XposedBridge.unhookMethod(uIs.getHookedMethod(), uIs.getCallback());
				}
				if (uOs != null)
					XposedBridge.unhookMethod(uOs.getHookedMethod(), uOs.getCallback());
				
				XposedBridge.log("android client connect");
				Socket clientSocket = (Socket) param.thisObject;

				XposedBridge.log("before");
				OutputStream os = clientSocket.getOutputStream();
				InputStream is = clientSocket.getInputStream();
				XposedBridge.log("after");

				/* debugging */
				XposedBridge.log(Integer
						.valueOf(clientSocket.getPort()).toString());

				DiffieHellman dh = new DiffieHellman(clientSocket);
				dh.negociate();

				/* debugging */
				String key = dh.getKey().toString(16);
				XposedBridge.log(key);

				AES aes = new AES(clientSocket);
				aes.setDhmKey(dh.getKey());
				aes.initAESEncryption();
				aes.initAESDecryption();
				aes.setOuputStream();
				aes.setInputStream();
				CryptOutputStream osCrypt = new CryptOutputStream(
						clientSocket, aes);
				CryptInputStream isCrypt = new CryptInputStream(
						clientSocket, aes);
				Streams stream = new Streams(isCrypt, osCrypt);
				keys.put(Integer.valueOf(clientSocket.getPort()),
							stream);
				
				uOs = findAndHookMethod("java.net.Socket", lpparam.classLoader, "getOutputStream", new XC_MethodReplacement() {
					@Override
					protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
						/* debugging */
						XposedBridge.log("In my getOutputStream");
						Object clientSocketObj = param.thisObject;

						if (clientSocketObj != null) {
							Socket clientSocket = (Socket) clientSocketObj;
							int port = clientSocket.getPort();
							/* debugging */
							XposedBridge.log("replacing getOutputStream");
							Streams streams = keys.get(Integer.valueOf(port));
							return streams.getCryptOs();
						}
						return null;
					}
				});
				
				uIs = findAndHookMethod("java.net.Socket", lpparam.classLoader, "getInputStream", new XC_MethodReplacement() {
					@Override
					protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
						/* debugging */
						XposedBridge.log("In my getInputStream");
						Object clientSocketObj = param.thisObject;

						if (clientSocketObj != null) {
							Socket clientSocket = (Socket) clientSocketObj;
							int port = clientSocket.getPort();
							/* debugging */
							XposedBridge.log("replacing getInputStream");
							Streams streams = keys.get(Integer.valueOf(port));
							return streams.getCryptIs();
						}
						return null;
					}
				});
			}
		});
	}
}