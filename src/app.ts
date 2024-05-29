import { decryptVaultData } from "./main.ts";
import { createVault, hybridEncrypt } from "./main.ts";

function validatedPrompt(
  question: string,
  validator: (response: string) => boolean,
) {
  let response = "";
  let firstPrompt = true;
  while (firstPrompt || !validator(response)) {
    response = prompt(question) ?? "";
    firstPrompt = false;
  }
  return response;
}

async function homePage() {
  console.clear();
  console.log(`%cVault CLI\n`, "font-weight: bold; color: #00f;");
  console.log("%c1%c - Create new vault", "color: #0f0", "");
  console.log("%c2%c - Encrypt data into vault", "color: #0f0", "");
  console.log("%c3%c - Decrypt data from vault", "color: #0f0", "");
  console.log("");

  const option = validatedPrompt(
    "Choose an option (1-3): ",
    (opt) => ["1", "2", "3"].includes(opt),
  );

  switch (option) {
    case "1":
      await createVaultPage();
      break;
    case "2":
      await encryptPage();
      break;
    case "3":
      await decryptPage();
      break;
  }
}

async function createVaultPage() {
  console.clear();
  console.log(
    `%cCreate new vault\n`,
    "font-weight: bold; color: #00f;",
  );

  console.log(
    "%cStep 1 - Choose the number of private key shares",
    "color: #00f;",
  );
  console.log(
    "The vault private key is used to decrypt data. It is split into multiple shares.",
  );
  console.log(
    "Each share is stored securely in different locations, or shared amongst different people.",
  );
  console.log(
    "A minimum number of shares (threshold) must be recombined to unlock the vault and decrypt data. You will set the threshold later.\n",
  );

  const numOfShares = validatedPrompt(
    "Enter number of private key shares (2-254): ",
    (res) => !isNaN(+res) && +res > 1 && +res < 255,
  );

  console.log(
    "\n%cStep 2 - Choose the threshold number of shares",
    "color: #00f;",
  );
  console.log(
    "This is the minimum number of shares that must be recombined to unlock the vault and decrypt data\n",
  );

  const threshold = validatedPrompt(
    `Enter threshold (2-${numOfShares}): `,
    (res) => !isNaN(+res) && +res > 1 && +res <= +numOfShares,
  );

  const vault = await createVault(+numOfShares, +threshold);

  console.clear();
  console.log("\n%cSuccessfully created new vault!\n", "color: #0f0;");

  for (
    let shareIndex = 0;
    shareIndex < vault.RSAPrivateKeyShares.length;
    shareIndex++
  ) {
    console.log(
      `\n%c---- BEGIN VAULT PRIVATE KEY SHARE ${
        shareIndex + 1
      } OF ${vault.RSAPrivateKeyShares.length} (THRESHOLD: ${threshold} REQUIRED TO RECOMBINE) ----`,
      "color: #f00; font-weight: bold;",
    );
    console.log(vault.RSAPrivateKeyShares[shareIndex]);
    console.log(
      `%c---- END VAULT PRIVATE KEY SHARE ${
        shareIndex + 1
      } OF ${vault.RSAPrivateKeyShares.length} ----`,
      "color: #f00; font-weight: bold;",
    );
  }

  console.log("\n%cVAULT PUBLIC KEY:", "color: #0f0");
  console.log(vault.RSAPublicKeyPEM);

  console.log(
    "\n%cInstructions",
    "color: #00f;",
  );
  console.log(
    "1. Safely and securely store each of the private key shares in different locations, or share with different people.",
  );
  console.log(
    "2. Copy the vault public key. This will be used to encrypt new data. This does not need to be protected.",
  );
  console.log(
    "3. Close this window and erase any centralised copies of the private key shares.\n",
  );
}

async function encryptPage() {
  console.clear();
  console.log(
    `%cEncrypt data\n`,
    "font-weight: bold; color: #00f;",
  );

  const RSAPublicKeyPEMInput = validatedPrompt(
    `Enter vault public key: `,
    () => true,
  );

  console.log("");
  const cleartext = validatedPrompt(
    `Enter text data to encrypt: `,
    () => true,
  );

  try {
    const ciphertext = await hybridEncrypt(RSAPublicKeyPEMInput, cleartext);
    console.clear();
    console.log(`%c\nSuccessfully encrypted data`, "color: #0f0;");
    console.log("\n%c---- BEGIN VAULT ENCRYPTED DATA ----", "color: #00f");
    console.log(ciphertext);
    console.log("%c---- END VAULT ENCRYPTED DATA ----", "color: #00f");
  } catch (e) {
    console.log(`\n%cError - could not encrypt data\n${e}`, "color: #f00;");
  }
}

async function decryptPage() {
  console.clear();
  console.log(
    `%cDecrypt data\n`,
    "font-weight: bold; color: #00f;",
  );

  console.log("%cStep 1 - Enter private key shares", "color: #00f;");
  console.log("Enter a single private key share and press [ENTER]");
  console.log("Enter additional private key shares one by one");
  console.log(
    "Once you have entered all the required shares, press [ENTER] again to continue",
  );

  const shares: string[] = [];
  let shareInput = "";

  while (shareInput != "" || shares.length < 2) {
    shareInput =
      prompt("\nEnter a private key share (or [ENTER] to continue): ") ?? "";
    if (shareInput.length > 0) {
      shares.push(shareInput);
    }
  }

  console.log("\n%cStep 2 - Enter encrypted data", "color: #00f;");
  console.log(
    "Now enter the vault encrypted data to decrypt, and press [ENTER]\n",
  );

  const encryptedData = validatedPrompt("Enter encrypted data: ", () => true);

  try {
    const cleartext = await decryptVaultData(shares, encryptedData);
    console.clear();
    console.log(`%c\nSuccessfully decrypted data\n`, "color: #0f0;");
    console.log(cleartext);
    console.log("\n");
  } catch (e) {
    console.log("\n%cError - could not decrypt data", "color: #f00;");
    console.log(
      "%c* Make sure the minimum number of private key shares are provided",
      "color: #f00;",
    );
    console.log(
      "%c* Make sure private key shares and encrypted data are formatted and entered correctly\n",
      "color: #f00;",
    );
    console.log(`%c${e}`, "color: #f00;");
  }
}

while (true) {
  await homePage();

  prompt("\n Press [ENTER] to return to home");
}
