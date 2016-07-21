/*
 * Copyright 2016 Jeremy Rand.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.libdohj.names;

import org.libdohj.script.NameScript;

import org.bitcoinj.core.Block;
import org.bitcoinj.core.BlockChain;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.core.ScriptException;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.core.listeners.NewBestBlockListener;
import org.bitcoinj.core.listeners.ReorganizeListener;
import org.bitcoinj.script.Script;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;

import org.fusesource.leveldbjni.*;
import org.iq80.leveldb.*;

import java.io.*;
import java.nio.*;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;

/*
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
*/

// TODO: document this

public class NameLookupLatestLevelDBTransactionCache implements NameLookupLatest, NewBestBlockListener, ReorganizeListener {
    
    
    protected static final byte[] CHAIN_HEAD_KEY = "Head".getBytes();
    protected static final byte[] HEIGHT_KEY = "Height".getBytes();
    
    protected BlockChain chain;
    protected BlockStore store;
    protected PeerGroup peerGroup;
    
    protected Context context;
    protected NetworkParameters params;
    protected File path;
    
    protected DB db;
    
    /*
    protected NameLookupByBlockHeight heightLookup;
    protected String restUrlPrefix;
    protected String restUrlSuffix;
    */
    
    public NameLookupLatestLevelDBTransactionCache (Context context, File directory, BlockChain chain, BlockStore store, PeerGroup peerGroup) throws Exception {
        this(context, directory, JniDBFactory.factory, chain, store, peerGroup);
    }
    
    public NameLookupLatestLevelDBTransactionCache (Context context, File directory, DBFactory dbFactory, BlockChain chain, BlockStore store, PeerGroup peerGroup) throws Exception {
        /*
        this.restUrlPrefix = restUrlPrefix;
        this.restUrlSuffix = restUrlSuffix;
        this.chain = chain;
        this.heightLookup = heightLookup;
        */
        
        this.chain = chain;
        this.store = store;
        this.peerGroup = peerGroup;
        
        this.context = context;
        this.params = context.getParams();
        
        this.path = directory;
        Options options = new Options();
        options.createIfMissing();
        
        try {
            tryOpen(directory, dbFactory, options);
        } catch (IOException e) {
            try {
                dbFactory.repair(directory, options);
                tryOpen(directory, dbFactory, options);
            } catch (IOException e1) {
                throw new Exception(e1);
            }
        }
        
        chain.addNewBestBlockListener(this);
        chain.addReorganizeListener(this);
    }
    
    protected void tryOpen(File directory, DBFactory dbFactory, Options options) throws IOException /* BlockStoreException */ {
        db = dbFactory.open(directory, options);
        initStoreIfNeeded();
    }
    
    protected synchronized void initStoreIfNeeded() /* throws BlockStoreException */ {
        if (db.get(CHAIN_HEAD_KEY) != null)
            return;   // Already initialised.
        
        setChainHead(0);
    }
    
    protected StoredBlock getSafeBlock(StoredBlock block) throws BlockStoreException {
        
        StoredBlock result = block;
        
        int safetyCount;
        for (safetyCount = 0; safetyCount < 12; safetyCount++) {
            result = result.getPrev(store);
        }
        
        return result;
    }
    
    protected synchronized void putBlockChain(StoredBlock block) throws Exception {
        
        // TODO: use BIP 113 timestamps
        if ( (new Date().getTime() / 1000 ) - block.getHeader().getTimeSeconds() > 366 * 24 * 60 * 60) {
            System.err.println("NameDB halting walkbalk due to timestamp expiration, height " + block.getHeight());
            return;
        }
        
        if (block.getHeight() > getChainHead() + 1) {
            putBlockChain(block.getPrev(store));
        }
        
        putBlock(block);
    }
    
    // TODO: try a different peer if downloading a block fails
    protected synchronized void putBlock(StoredBlock block) throws Exception /* throws BlockStoreException */ {
        
        Sha256Hash blockHash = block.getHeader().getHash();
        
        Block nameFullBlock = peerGroup.getDownloadPeer().getBlock(blockHash).get();
        
        // The full block hasn't been verified in any way!
        // So let's do that now.
        
        if (! nameFullBlock.getHash().equals(blockHash)) {
            throw new Exception("Block hash mismatch!");
        }
        
        // Now we know that the received block actually does match the hash that we requested.
        // However, that doesn't mean that the block's contents are valid.
        
        final EnumSet<Block.VerifyFlag> flags = EnumSet.noneOf(Block.VerifyFlag.class);
        nameFullBlock.verify(-1, flags);
        
        // Now we know that the block is internally valid (including the merkle root).
        // We haven't verified signature validity, but our threat model is SPV.
        
        int height = block.getHeight();
        
        for (Transaction tx : nameFullBlock.getTransactions()) {
            for (TransactionOutput output : tx.getOutputs()) {
                try {
                    Script scriptPubKey = output.getScriptPubKey();
                    NameScript ns = new NameScript(scriptPubKey);
                    if(ns.isNameOp() && ns.isAnyUpdate() ) {
                        putNameTransaction(ns.getOpName().data, tx, height);
                    }
                } catch (ScriptException e) {
                    continue;
                }
            }
        }
        
        setChainHead(block.getHeight());
    }
    
    protected synchronized void putNameTransaction(final byte[] nameBytes, Transaction tx, int height) /* throws BlockStoreException */ {
        
        // TODO: check if name is relevant (e.g. namespace is id/, has zeronet field)
        
        byte[] headerBytes = "NameTx".getBytes();
        // name goes here
        
        // height goes here
        byte[] txBytes = tx.bitcoinSerialize();
        
        ByteBuffer keyBuffer = ByteBuffer.allocate(headerBytes.length + nameBytes.length);
        ByteBuffer recordBuffer = ByteBuffer.allocate(4 + txBytes.length);
        
        keyBuffer.put(headerBytes).put(nameBytes);
        recordBuffer.putInt(height).put(txBytes);
        
        db.put(keyBuffer.array(), recordBuffer.array());
    }
    
    // TODO: stop duplicating code from the other NameLookupLatest implementations
    protected void verifyHeightTrustworthy(int height) throws Exception {
        if (height < 1) {
            throw new Exception("Nonpositive block height; not trustworthy!");
        }
        
        int headHeight = chain.getChainHead().getHeight();
        
        int confirmations = headHeight - height + 1;
        
        // TODO: optionally use transaction chains (with signature checks) to verify transactions without 12 confirmations
        // TODO: the above needs to be optional, because some applications (e.g. cert transparency) require confirmations
        if (confirmations < 12) {
            throw new Exception("Block does not yet have 12 confirmations; not trustworthy!");
        }
        
        // TODO: check for off-by-one errors on this line
        if (confirmations >= 36000) {
            throw new Exception("Block has expired; not trustworthy!");
        }
    }
    
    // TODO: make a new Exception class
    @Override
    public Transaction getNameTransaction(String name, String identity) throws Exception {
        
        byte[] headerBytes = "NameTx".getBytes("ISO-8859-1");
        byte[] nameBytes = name.getBytes("ISO-8859-1");
        // name goes here
        
        ByteBuffer keyBuffer = ByteBuffer.allocate(headerBytes.length + nameBytes.length);
        keyBuffer.put(headerBytes).put(nameBytes);
        
        byte[] recordBytes = db.get(keyBuffer.array());
        if (recordBytes == null)
            return null;
        
        ByteBuffer recordBuffer = ByteBuffer.wrap(recordBytes);
        
        int height = recordBuffer.getInt();
        
        verifyHeightTrustworthy(height);
        
        Transaction tx = new Transaction(params, recordBytes, 4);
        
        tx.getConfidence().setAppearedAtChainHeight(height); // TODO: test this line
        tx.getConfidence().setDepthInBlocks(chain.getChainHead().getHeight() - height + 1);
        
        return tx;
    }
    
    protected synchronized int getChainHead() /* throws BlockStoreException */ {
        return ByteBuffer.wrap(db.get(CHAIN_HEAD_KEY)).getInt();
    }
    
    protected synchronized void setChainHead(int chainHead) /* throws BlockStoreException */ {
        db.put(CHAIN_HEAD_KEY, ByteBuffer.allocate(4).putInt(chainHead).array());
    }
    
    public synchronized void close() throws Exception {
        try {
            db.close();
        } catch (IOException e) {
            throw new Exception(e);
        }
    }
    
    /** Erases the contents of the database (but NOT the underlying files themselves) and then reinitialises with the genesis block. */
    protected synchronized void reset() throws Exception {
        try {
            WriteBatch batch = db.createWriteBatch();
            try {
                DBIterator it = db.iterator();
                try {
                    it.seekToFirst();
                    while (it.hasNext())
                        batch.delete(it.next().getKey());
                    db.write(batch);
                } finally {
                    it.close();
                }
            } finally {
                batch.close();
            }
            initStoreIfNeeded();
        } catch (IOException e) {
            throw new Exception(e);
        }
    }
    
    protected synchronized void destroy() throws IOException {
        JniDBFactory.factory.destroy(path, new Options());
    }
    
    @Override
    public void notifyNewBestBlock (StoredBlock block) throws VerificationException {
        // TODO: use BIP 113 timestamps
        if ( (new Date().getTime() / 1000 ) - block.getHeader().getTimeSeconds() > 366 * 24 * 60 * 60) {
            System.err.println("NameDB skipping notifyNewBestBlock height " + block.getHeight() + " due to timestamp " + block.getHeader().getTimeSeconds());
            return;
        }
        
        System.err.println("Entering notifyNewBestBlock at height " + block.getHeight());
        
        try {
            putBlockChain(getSafeBlock(block));
        }
        catch (Exception e) {
            System.err.println("Exception during NameDB notifyNewBestBlock: " + e);
            throw new VerificationException(e);
        }
        
        System.err.println("Finished NameDB notifyNewBestBlock, height " + block.getHeight());
    }
    
    // WARNING: in a reorg that is at least 12 blocks deep, any names updated in the old blocks that aren't updated in the new blocks will remain in their old state in the database.
    // That is incorrect behavior, but it usually isn't advantageous to an attacker.
    // In certain applications where proof of existence is used, this incorrect behavior could allow a true existence claim to be accepted,
    // even though the rest of the network will incorrectly reject it.
    // I don't see any other significant attacks here.  Have I missed something?
    // If we're really worried about this, the "right" solution is to either store name history in the database,
    // or redownload all of the last 36 kiloblocks.
    @Override
    public void reorganize(StoredBlock splitPoint, List<StoredBlock> oldBlocks, List<StoredBlock> newBlocks) throws VerificationException {
        // TODO: use BIP 113 timestamps
        if ( (new Date().getTime() / 1000 ) - newBlocks.get(0).getHeader().getTimeSeconds() > 366 * 24 * 60 * 60) {
            return;
        }
        
        setChainHead(splitPoint.getHeight() - 12);
        
        try {
            putBlockChain(getSafeBlock(newBlocks.get(0)));
        }
        catch (Exception e) {
            System.err.println("Exception during NameDB reorganize: " + e);
            throw new VerificationException(e);
        }
        
        System.err.println("Finished NameDB reorganize, height " + newBlocks.get(0).getHeight());
    }
}
