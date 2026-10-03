import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const databasePath = path.join(__dirname, 'subscribers.json');

export function getSubscriber(imsi) {
    const database = JSON.parse(fs.readFileSync(databasePath, 'utf8'));
    const subscriber = database[imsi];

    if (!subscriber) {
        return null;
    }

    if (!subscriber.enabled) {
        return null;
    }

    return {
        ...subscriber,
        ki: Buffer.from(subscriber.ki, 'hex'),
        opc: Buffer.from(subscriber.opc, 'hex'),
        amf: Buffer.from(subscriber.amf, 'hex'),
        sqn: Buffer.from(subscriber.sqn, 'hex')
    };
}

export function incrementSQN(imsi) {
    const database = JSON.parse(fs.readFileSync(databasePath, 'utf8'));
    const subscriber = database[imsi];

    if (!subscriber) {
        throw new Error(`Subscriber ${imsi} not found`);
    }

    const currentSQN = BigInt(`0x${subscriber.sqn}`);
    const nextSQN = currentSQN + 1n;

    subscriber.sqn = nextSQN.toString(16).padStart(12, '0');
    database[imsi] = subscriber;

    fs.writeFileSync(
        databasePath,
        JSON.stringify(database, null, 4)
    );

    return Buffer.from(
        subscriber.sqn,
        'hex'
    );
}