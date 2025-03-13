import { Ed25519Signature2018 } from "@transmute/ed25519-signature-2018";
import { documentLoaderFactory } from "@transmute/jsonld-document-loader";
import { VerifiablePresentation } from "@transmute/verifiable-credentials";

/**
 * Function to validate the proof of a Linked Verifiable Presentation (VP)
 * @param {VerifiablePresentation} vp - The Verifiable Presentation to validate
 * @returns {Promise<boolean>} - True if the proof is valid, false otherwise
 */
export async function verifyLinkedVP(vp: VerifiablePresentation): Promise<boolean> {
  try {
    if (!vp || !vp.proof) {
      throw new Error("The Verifiable Presentation does not contain a valid proof.");
    }

    const suite = new Ed25519Signature2018();
    type ProofType = typeof vp.proof;

    const result = await suite.verifyProof({
      proof: vp.proof,
      document: vp,
      purpose: {
        validate: () => ({ valid: true }),
        update: (proof: ProofType) => proof,
      },
      documentLoader: customDocumentLoader,
    });
    return result.verified;
  } catch (error) {
    console.error("Error validating the proof:", error.message);
    return false;
  }
}

// TODO: Review this implementation to determine which one we can use.
export const customDocumentLoader = documentLoaderFactory.build({
  restrictedTo: ["https://www.w3.org/2018/credentials/v1", "https://schema.org/"]
});
