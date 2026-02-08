import { createInterface } from 'readline';
import { encrypt, decrypt } from './encryptDecryptHelper.js';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Create readline interface for console input
const rl = createInterface({
    input: process.stdin,
    output: process.stdout
});

/**
 * Promisified question helper
 * @param {string} question - Question to ask
 * @returns {Promise<string>} User input
 */
function question(question) {
    return new Promise((resolve) => {
        rl.question(question, (answer) => {
            resolve(answer);
        });
    });
}

/**
 * Console colors helper
 */
const colors = {
    reset: '\x1b[0m',
    cyan: '\x1b[36m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    red: '\x1b[31m'
};

/**
 * Load and validate environment variables
 * @returns {{ publicKey: string, privateKey: string } | null}
 */
function loadEnvironmentVariables() {
    try {
        const publicKey = process.env.RSA_PUBLIC_KEY;
        const privateKey = process.env.RSA_PRIVATE_KEY;

        if (!publicKey || !privateKey) {
            console.log(`${colors.red}ERROR: RSA keys not found in .env file!`);
            console.log('Please ensure RSA_PUBLIC_KEY and RSA_PRIVATE_KEY are defined in .env');
            console.log(`Public Key found: ${!!publicKey}`);
            console.log(`Private Key found: ${!!privateKey}${colors.reset}`);
            return null;
        }

        console.log(`${colors.green}✓ Environment variables loaded successfully${colors.reset}\n`);
        return { publicKey, privateKey };
    } catch (error) {
        console.log(`${colors.red}ERROR: Failed to load .env file - ${error.message}${colors.reset}`);
        return null;
    }
}

/**
 * Display application banner
 */
function showBanner() {
    console.log(`${colors.cyan}╔═══════════════════════════════════════════════════════════╗`);
    console.log(`║                                                           ║`);
    console.log(`║        HYBRID ENCRYPTION - AES 256 + RSA 2048             ║`);
    console.log(`║              Node.js Console Application                  ║`);
    console.log(`║                                                           ║`);
    console.log(`╚═══════════════════════════════════════════════════════════╝${colors.reset}`);
    console.log();
}

/**
 * Display menu options
 */
function showMenuOptions() {
    console.log('\n════════════════ MENU UTAMA ════════════════');
    console.log();
    console.log('  [1] Encrypt Text');
    console.log('  [2] Decrypt Text');
    console.log('  [0] Exit');
    console.log();
    console.log('════════════════════════════════════════════');
}

/**
 * Encrypt text handler
 * @param {string} publicKey - RSA public key
 */
async function encryptText(publicKey) {
    console.log('\n────────────── ENCRYPT TEXT ──────────────');
    const plainText = await question('\nMasukkan teks yang akan di-encrypt: ');

    if (!plainText || plainText.trim() === '') {
        console.log(`${colors.red}❌ Teks tidak boleh kosong!${colors.reset}`);
        return;
    }

    try {
        const result = encrypt(plainText, publicKey);

        console.log(`${colors.green}\n✅ Enkripsi berhasil!${colors.reset}`);
        console.log('\n📦 Hasil Enkripsi:');
        console.log('─────────────────────────────────────────────');
        console.log(`${colors.yellow}Data (Encrypted): ${result.data}`);
        console.log(`AES Key (RSA Encrypted): ${result.aes}`);
        console.log(`IV: ${result.iv}${colors.reset}`);
    } catch (error) {
        console.log(`${colors.red}\n❌ Error saat enkripsi: ${error.message}${colors.reset}`);
    }
}

/**
 * Decrypt text handler
 * @param {string} privateKey - RSA private key
 */
async function decryptText(privateKey) {
    console.log('\n────────────── DECRYPT TEXT ──────────────');

    const encryptedData = await question('\nMasukkan Data (encrypted text): ');
    const encryptedAesKey = await question('Masukkan AES Key (RSA encrypted): ');
    const iv = await question('Masukkan IV: ');

    if (!encryptedData || !encryptedAesKey || !iv ||
        encryptedData.trim() === '' || encryptedAesKey.trim() === '' || iv.trim() === '') {
        console.log(`${colors.red}❌ Semua field harus diisi!${colors.reset}`);
        return;
    }

    try {
        const request = {
            data: encryptedData.trim(),
            aes: encryptedAesKey.trim(),
            iv: iv.trim()
        };

        const decryptedText = decrypt(request, privateKey);

        console.log(`${colors.green}\n✅ Dekripsi berhasil!${colors.reset}`);
        console.log('\n📄 Hasil Dekripsi:');
        console.log('─────────────────────────────────────────────');
        console.log(`${colors.cyan}${decryptedText}${colors.reset}`);
    } catch (error) {
        console.log(`${colors.red}\n❌ Error saat dekripsi: ${error.message}${colors.reset}`);
    }
}

/**
 * Main menu loop
 * @param {string} publicKey - RSA public key
 * @param {string} privateKey - RSA private key
 */
async function runMenu(publicKey, privateKey) {
    let isRunning = true;

    while (isRunning) {
        showMenuOptions();
        const input = await question('\nPilih menu: ');

        switch (input.trim()) {
            case '1':
                await encryptText(publicKey);
                break;
            case '2':
                await decryptText(privateKey);
                break;
            case '0':
                console.log(`${colors.yellow}\n👋 Terima kasih telah menggunakan aplikasi ini!${colors.reset}`);
                isRunning = false;
                break;
            default:
                console.log(`${colors.red}\n❌ Pilihan tidak valid. Silakan coba lagi.${colors.reset}`);
                break;
        }
    }

    rl.close();
}

/**
 * Main entry point
 */
async function main() {
    const keys = loadEnvironmentVariables();
    if (!keys) {
        rl.close();
        return;
    }

    showBanner();
    await runMenu(keys.publicKey, keys.privateKey);
}

// Run the application
main().catch((error) => {
    console.error(`${colors.red}Fatal error: ${error.message}${colors.reset}`);
    rl.close();
    process.exit(1);
});
