package io.github.serengil.lightphe.ecc.curves;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Read-only inventory of the standard elliptic curves shipped with the library, grouped by form.
 *
 * <p>This is the Java counterpart of {@code lightecc.curves.inventory}. Curve names are normalised
 * to lower case with underscores replaced by hyphens, exactly as the Python implementation derives
 * them from its class names.
 */
public final class CurveRegistry {

    private CurveRegistry() {
        throw new AssertionError("no instances");
    }

    /**
     * Lists the curves supported for a given form, in the order they appear in the inventory.
     *
     * @param form the curve form
     * @return the names of every curve of that form
     */
    public static List<String> listCurves(CurveForm form) {
        return switch (form) {
            case WEIERSTRASS -> List.copyOf(WeierstrassData.curves().keySet());
            case EDWARDS -> List.copyOf(EdwardsData.curves().keySet());
            case KOBLITZ -> List.copyOf(KoblitzData.curves().keySet());
        };
    }

    /**
     * Lists every supported curve form.
     *
     * @return all curve forms
     */
    public static List<CurveForm> forms() {
        return Collections.unmodifiableList(new ArrayList<>(List.of(CurveForm.values())));
    }

    /**
     * Looks up a short Weierstrass curve by name.
     *
     * @param name curve name; {@code null} or blank selects the form's default curve
     * @return the parameters of the named curve
     * @throws IllegalArgumentException when no such curve exists
     */
    public static WeierstrassParams weierstrass(String name) {
        String key = normalise(name, CurveForm.WEIERSTRASS);
        WeierstrassParams params = WeierstrassData.curves().get(key);
        if (params == null) {
            throw new IllegalArgumentException("Unsupported weierstrass curve - " + name);
        }
        return params;
    }

    /**
     * Looks up a twisted Edwards curve by name.
     *
     * @param name curve name; {@code null} or blank selects the form's default curve
     * @return the parameters of the named curve
     * @throws IllegalArgumentException when no such curve exists
     */
    public static EdwardsParams edwards(String name) {
        String key = normalise(name, CurveForm.EDWARDS);
        EdwardsParams params = EdwardsData.curves().get(key);
        if (params == null) {
            throw new IllegalArgumentException("Unsupported edwards curve - " + name);
        }
        return params;
    }

    /**
     * Looks up a Koblitz curve by name.
     *
     * @param name curve name; {@code null} or blank selects the form's default curve
     * @return the parameters of the named curve
     * @throws IllegalArgumentException when no such curve exists
     */
    public static KoblitzParams koblitz(String name) {
        String key = normalise(name, CurveForm.KOBLITZ);
        KoblitzParams params = KoblitzData.curves().get(key);
        if (params == null) {
            throw new IllegalArgumentException("Unsupported koblitz curve - " + name);
        }
        return params;
    }

    private static String normalise(String name, CurveForm form) {
        if (name == null || name.isBlank()) {
            return form.defaultCurve();
        }
        return name.trim().toLowerCase(Locale.ROOT).replace('_', '-');
    }
}
