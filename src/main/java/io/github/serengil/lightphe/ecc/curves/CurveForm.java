package io.github.serengil.lightphe.ecc.curves;

import java.util.Locale;

/**
 * The shape of the equation an elliptic curve is written in.
 *
 * <p>Every form comes with its own default curve, used when a caller selects a form without naming
 * a specific curve.
 */
public enum CurveForm {

    /** {@code y^2 = x^3 + a*x + b} over the prime field {@code F_p}. */
    WEIERSTRASS("weierstrass", "secp256k1"),

    /** {@code a*x^2 + y^2 = 1 + d*x^2*y^2} over the prime field {@code F_p}. */
    EDWARDS("edwards", "ed25519"),

    /** {@code y^2 + x*y = x^3 + a*x^2 + b} over the binary field {@code F_{2^m}}. */
    KOBLITZ("koblitz", "k163");

    private final String formName;
    private final String defaultCurve;

    CurveForm(String formName, String defaultCurve) {
        this.formName = formName;
        this.defaultCurve = defaultCurve;
    }

    /**
     * Returns the lower-case name used by the Python reference implementation, e.g. {@code
     * "weierstrass"}.
     *
     * @return the wire name of this form
     */
    public String formName() {
        return formName;
    }

    /**
     * Returns the curve selected when this form is requested without naming a curve.
     *
     * @return the default curve name for this form
     */
    public String defaultCurve() {
        return defaultCurve;
    }

    /**
     * Resolves a form from its textual name, case-insensitively.
     *
     * @param name form name, e.g. {@code "edwards"}; {@code null} or blank yields {@link
     *     #WEIERSTRASS}
     * @return the matching form
     * @throws IllegalArgumentException when no form carries that name
     */
    public static CurveForm of(String name) {
        if (name == null || name.isBlank()) {
            return WEIERSTRASS;
        }
        String needle = name.trim().toLowerCase(Locale.ROOT);
        for (CurveForm form : values()) {
            if (form.formName.equals(needle)) {
                return form;
            }
        }
        throw new IllegalArgumentException("unimplemented curve form - " + name);
    }

    @Override
    public String toString() {
        return formName;
    }
}
