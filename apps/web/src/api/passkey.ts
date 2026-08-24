/**
 * Die Passkey-Zeremonien im Browser.
 *
 * **Was hier ausdrücklich nicht stattfindet: eine Prüfung.** Der Browser
 * signiert, der Server prüft. Diese Datei überträgt zwischen zwei Formaten —
 * die API spricht JSON, `navigator.credentials` spricht `ArrayBuffer`.
 *
 * Die Umwandlung ist der einzige heikle Teil, und sie ist heikel auf eine
 * langweilige Art: base64url ist nicht base64 (`-_` statt `+/`, keine
 * Auffüllung). Wer das verwechselt, bekommt eine Signatur über andere Bytes
 * als die geprüften — und einen Fehler, der wie ein Angriff aussieht.
 */

type Zeremonie = { options: Record<string, unknown>; challenge: string };

export async function registrieren(zeremonie: Zeremonie): Promise<unknown> {
  const optionen = alsCreationOptions(zeremonie.options);
  const nachweis = (await navigator.credentials.create({
    publicKey: optionen,
  })) as PublicKeyCredential | null;
  if (nachweis === null) {
    throw new Error("Die Registrierung wurde abgebrochen.");
  }
  return alsJson(nachweis);
}

export async function anmelden(zeremonie: Zeremonie): Promise<unknown> {
  const optionen = alsRequestOptions(zeremonie.options);
  const nachweis = (await navigator.credentials.get({
    publicKey: optionen,
  })) as PublicKeyCredential | null;
  if (nachweis === null) {
    throw new Error("Die Anmeldung wurde abgebrochen.");
  }
  return alsJson(nachweis);
}

/**
 * Die Antwort des Authenticators als JSON.
 *
 * `toJSON()` ist der vorgesehene Weg und liefert genau das Format, das der
 * Server erwartet. Ältere Browser kennen es nicht; für sie steht die
 * Umwandlung von Hand daneben. Sie ist keine Notlösung, sondern derselbe
 * Vertrag — nur ausgeschrieben.
 */
function alsJson(nachweis: PublicKeyCredential): unknown {
  const mitToJson = nachweis as PublicKeyCredential & { toJSON?: () => unknown };
  if (typeof mitToJson.toJSON === "function") {
    return mitToJson.toJSON();
  }

  const antwort = nachweis.response;
  const felder: Record<string, string> = {
    clientDataJSON: b64url(antwort.clientDataJSON),
  };
  if ("attestationObject" in antwort) {
    felder.attestationObject = b64url(
      (antwort as AuthenticatorAttestationResponse).attestationObject,
    );
  } else {
    const anmeldung = antwort as AuthenticatorAssertionResponse;
    felder.authenticatorData = b64url(anmeldung.authenticatorData);
    felder.signature = b64url(anmeldung.signature);
    if (anmeldung.userHandle) felder.userHandle = b64url(anmeldung.userHandle);
  }

  return {
    id: nachweis.id,
    rawId: b64url(nachweis.rawId),
    type: nachweis.type,
    response: felder,
    clientExtensionResults: nachweis.getClientExtensionResults(),
  };
}

function alsCreationOptions(roh: Record<string, unknown>): PublicKeyCredentialCreationOptions {
  const eingebaut = (
    PublicKeyCredential as unknown as {
      parseCreationOptionsFromJSON?: (j: unknown) => PublicKeyCredentialCreationOptions;
    }
  ).parseCreationOptionsFromJSON;
  if (eingebaut) return eingebaut(roh);

  const optionen = { ...roh } as Record<string, unknown>;
  optionen.challenge = unb64url(roh.challenge as string);
  const nutzer = { ...(roh.user as Record<string, unknown>) };
  nutzer.id = unb64url(nutzer.id as string);
  optionen.user = nutzer;
  optionen.excludeCredentials = (
    (roh.excludeCredentials as Array<Record<string, unknown>>) ?? []
  ).map((eintrag) => ({ ...eintrag, id: unb64url(eintrag.id as string) }));
  return optionen as unknown as PublicKeyCredentialCreationOptions;
}

function alsRequestOptions(roh: Record<string, unknown>): PublicKeyCredentialRequestOptions {
  const eingebaut = (
    PublicKeyCredential as unknown as {
      parseRequestOptionsFromJSON?: (j: unknown) => PublicKeyCredentialRequestOptions;
    }
  ).parseRequestOptionsFromJSON;
  if (eingebaut) return eingebaut(roh);

  const optionen = { ...roh } as Record<string, unknown>;
  optionen.challenge = unb64url(roh.challenge as string);
  optionen.allowCredentials = (
    (roh.allowCredentials as Array<Record<string, unknown>>) ?? []
  ).map((eintrag) => ({ ...eintrag, id: unb64url(eintrag.id as string) }));
  return optionen as unknown as PublicKeyCredentialRequestOptions;
}

function b64url(puffer: ArrayBuffer): string {
  const bytes = new Uint8Array(puffer);
  let roh = "";
  for (const byte of bytes) roh += String.fromCharCode(byte);
  return btoa(roh).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unb64url(wert: string): ArrayBuffer {
  const aufgefuellt = wert.replace(/-/g, "+").replace(/_/g, "/");
  const roh = atob(aufgefuellt.padEnd(Math.ceil(aufgefuellt.length / 4) * 4, "="));
  const bytes = new Uint8Array(roh.length);
  for (let i = 0; i < roh.length; i += 1) bytes[i] = roh.charCodeAt(i);
  return bytes.buffer;
}
