/* dlopen target. */
int plugin_probe(int x) { return x * 3 + 1; }
const char *plugin_name(void) { return "lexe-workload-plugin"; }
