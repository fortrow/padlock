#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x9aa6980d, "mutex_lock" },
	{ 0xee26d75d, "const_current_task" },
	{ 0x9aa6980d, "mutex_unlock" },
	{ 0xe4de56b4, "__ubsan_handle_load_invalid_value" },
	{ 0x092a35a2, "_copy_from_user" },
	{ 0x092a35a2, "_copy_to_user" },
	{ 0x224a53e7, "get_random_bytes" },
	{ 0x90a48d82, "__ubsan_handle_out_of_bounds" },
	{ 0x31ea07ad, "module_put" },
	{ 0x7ed256c3, "noop_llseek" },
	{ 0xd272d446, "__fentry__" },
	{ 0xbd03ed67, "__ref_stack_chk_guard" },
	{ 0xaa178104, "kern_path" },
	{ 0xfedd0192, "path_put" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0xb6377019, "register_kprobe" },
	{ 0x9aa6980d, "mutex_init_generic" },
	{ 0xa038bfdb, "misc_register" },
	{ 0xfe5fb05c, "try_module_get" },
	{ 0xe8213e80, "_printk" },
	{ 0x00b48d44, "misc_deregister" },
	{ 0x2de0a194, "unregister_kprobe" },
	{ 0xd954c786, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0x9aa6980d,
	0xee26d75d,
	0x9aa6980d,
	0xe4de56b4,
	0x092a35a2,
	0x092a35a2,
	0x224a53e7,
	0x90a48d82,
	0x31ea07ad,
	0x7ed256c3,
	0xd272d446,
	0xbd03ed67,
	0xaa178104,
	0xfedd0192,
	0xd272d446,
	0xb6377019,
	0x9aa6980d,
	0xa038bfdb,
	0xfe5fb05c,
	0xe8213e80,
	0x00b48d44,
	0x2de0a194,
	0xd954c786,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"mutex_lock\0"
	"const_current_task\0"
	"mutex_unlock\0"
	"__ubsan_handle_load_invalid_value\0"
	"_copy_from_user\0"
	"_copy_to_user\0"
	"get_random_bytes\0"
	"__ubsan_handle_out_of_bounds\0"
	"module_put\0"
	"noop_llseek\0"
	"__fentry__\0"
	"__ref_stack_chk_guard\0"
	"kern_path\0"
	"path_put\0"
	"__stack_chk_fail\0"
	"register_kprobe\0"
	"mutex_init_generic\0"
	"misc_register\0"
	"try_module_get\0"
	"_printk\0"
	"misc_deregister\0"
	"unregister_kprobe\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "C9609AEAB94F565D9B76255");
