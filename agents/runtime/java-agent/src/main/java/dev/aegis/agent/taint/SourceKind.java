package dev.aegis.agent.taint;

/** Where attacker-controllable data entered the application. */
public enum SourceKind {
    PARAMETER,
    HEADER,
    COOKIE,
    BODY,
    PATH,
    QUERY_STRING,
    MESSAGE_QUEUE,
    /** Second-order: data read back out of storage that was attacker-controlled going in. */
    DATABASE,
    FILE;

    public String wireName() {
        return "SOURCE_KIND_" + name();
    }
}
