package me.grax.gezkm;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import me.grax.gezkm.utils.FieldChangeListener;
import me.grax.gezkm.utils.FieldUtils;
import me.grax.gezkm.utils.InstructionUtils;
import me.grax.gezkm.utils.MethodUtils;
import me.lpk.util.ASMUtils;
import me.lpk.util.AccessHelper;

public class Deobfuscator {

	public static void startDeobfuscation(Map<String, ClassNode> classes, Map<String, byte[]> other) {
		//load everything first
		classes.values().forEach(cn -> {
			MethodNode cmn = MethodUtils.getClinit(cn);
			if (cmn != null) {
				cmn.name = "init_zkm"; //to allow reflection

					cmn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC;
			}
			loadClass(cn);
		});

		classes.values().forEach(cn -> {
			try {
				initStrings(cn);
			} catch (Exception e) {
				e.printStackTrace();
			}
		});
	}

	private static void initStrings(ClassNode cn) throws Exception {
		Class c = Main.classLoader.loadClass(cn.name.replace("/", "."));
		if (c == null) {
			System.err.println("Class " + cn.name + " not found, skipping.");
			return;
		}
		Method clinit = null;
		try {
			clinit = c.getMethod("init_zkm");
		} catch (Throwable t) {
			System.err.println("no clinit in class " + cn.name);
		}
		if (clinit == null) {
			return;
		}
		clinit.setAccessible(true);
		FieldChangeListener fcl = new FieldChangeListener(c);
		clinit.invoke(null);
		replaceSimple(c, fcl.check(), cn);
		MethodNode cmn = MethodUtils.getMethod(cn, "init_zkm");
		cmn.name = "<clinit>";
	}

	private static void replaceSimple(Class c, ArrayList<Field> check, ClassNode cn) throws Exception {
//		scanForSingleStringReplacement(cn, check);
//		scanForMultiStringReplacement(c, cn, check);
		scanForWeirdStringerObfuscation(c, cn);
	}

	private static void scanForWeirdStringerObfuscation(Class c, ClassNode cn) {
		cn.methods.forEach(mn -> {
			for (AbstractInsnNode ain : mn.instructions.toArray()) {
				if (ain.getOpcode() == Opcodes.INVOKESTATIC) { //enchanced multi
					MethodInsnNode min = (MethodInsnNode) ain;
					if (min.desc.equals("(Ljava/lang/String;I)Ljava/lang/String;") && min.owner.equals(cn.name)) {
						if (ain.getPrevious() != null && ain.getPrevious().getPrevious() != null) {
							if (InstructionUtils.isNumber(ain.getPrevious()) && (ain.getPrevious().getPrevious().getType() == AbstractInsnNode.LDC_INSN)) {
								String str1 = InstructionUtils.getStringValue(ain.getPrevious().getPrevious());
								int num2 = InstructionUtils.getIntValue(ain.getPrevious());

								try {
									Method decrypt = c.getDeclaredMethod(min.name, String.class, int.class);
									decrypt.setAccessible(true);
									String value = (String) decrypt.invoke(null, str1, num2);
									System.out.println(value);
									if (value != null) {
										mn.instructions.remove(ain.getPrevious().getPrevious());
										mn.instructions.remove(ain.getPrevious());
										mn.instructions.set(ain, new LdcInsnNode(value));
									}
								} catch (Throwable e) {
									e.printStackTrace();
								}
							}
						}
					}
				}
			}
		});
	}

	private static void scanForSingleStringReplacement(ClassNode cn, ArrayList<Field> changed) throws Exception {
		HashMap<FieldNode, Object> fns = new HashMap<>();
		for (Field f : changed) {
			Object value = f.get(null);
			if (value == null) {
				continue;
			}
			FieldNode fn = FieldUtils.findTreeField(cn, f);
			fns.put(fn, value);
		}
		cn.methods.forEach(mn -> {
			for (AbstractInsnNode ain : mn.instructions.toArray()) {
				if (ain.getOpcode() == Opcodes.GETSTATIC) { //simple
					FieldInsnNode fin = (FieldInsnNode) ain;
					for (FieldNode fn : fns.keySet()) {
						if (fn.desc.equals("Ljava/lang/String;"))
							if (fin.desc.equals(fn.desc) && fin.owner.equals(cn.name) && fin.name.equals(fn.name)) {
								mn.instructions.set(fin, new LdcInsnNode(fns.get(fn)));
							}
					}
				}
			}
		});
	}

	private static void scanForMultiStringReplacement(Class c, ClassNode cn, ArrayList<Field> changed) throws Exception {
		HashMap<FieldNode, Object> fns = new HashMap<>();
		for (Field f : changed) {
			Object value = f.get(null);
			if (value == null) {
				continue;
			}
			FieldNode fn = FieldUtils.findTreeField(cn, f);
			fns.put(fn, value);
		}
		cn.methods.forEach(mn -> {
			for (AbstractInsnNode ain : mn.instructions.toArray()) {
				if (ain.getOpcode() == Opcodes.INVOKESTATIC) { //enchanced multi
					MethodInsnNode min = (MethodInsnNode) ain;
					if (min.desc.equals("(II)Ljava/lang/String;") && min.owner.equals(cn.name)) {
						if (ain.getPrevious() != null && ain.getPrevious().getPrevious() != null) {
							if (InstructionUtils.isNumber(ain.getPrevious()) && InstructionUtils.isNumber(ain.getPrevious().getPrevious())) {
								int num1 = InstructionUtils.getIntValue(ain.getPrevious().getPrevious());
								int num2 = InstructionUtils.getIntValue(ain.getPrevious());

								try {
									Method decrypt = c.getDeclaredMethod(min.name, int.class, int.class);
									decrypt.setAccessible(true);
									String value = (String) decrypt.invoke(null, num1, num2);
									if (value != null) {
										mn.instructions.remove(ain.getPrevious().getPrevious());
										mn.instructions.remove(ain.getPrevious());
										mn.instructions.set(ain, new LdcInsnNode(value));
									}
								} catch (Throwable e) {
									e.printStackTrace();
								}
							}
						}
					}
				}
			}
		});
	}

	private static void loadClass(ClassNode cn) {
		Main.classLoader.classes.put(cn.name + ".class", ASMUtils.getNodeBytes(cn, true));
	}

}
