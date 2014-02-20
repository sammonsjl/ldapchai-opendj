/*
 * LDAP Chai API
 * Copyright (c) 2006-2010 Novell, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package com.novell.ldapchai.impl.ad.entry;

import com.novell.ldapchai.ChaiEntry;
import com.novell.ldapchai.ChaiFactory;
import com.novell.ldapchai.ChaiGroup;
import com.novell.ldapchai.exception.ErrorMap;
import com.novell.ldapchai.impl.ad.ADErrorMap;
import com.novell.ldapchai.provider.ChaiProvider;

public class ADEntryFactory implements ChaiFactory.ChaiEntryFactory {

    private static ErrorMap errorMap;

    public User createChaiUser(final String userDN, final ChaiProvider chaiProvider) {
        return new UserImpl(userDN, chaiProvider);
    }

    public ChaiGroup createChaiGroup(final String entryDN, final ChaiProvider provider) {
        return new GroupImpl(entryDN, provider);
    }

    public ChaiEntry createChaiEntry(final String entryDN, final ChaiProvider provider) {
        return new TopImpl(entryDN, provider);
    }

    public ChaiProvider.DIRECTORY_VENDOR getDirectoryVendor() {
        return ChaiProvider.DIRECTORY_VENDOR.MICROSOFT_ACTIVE_DIRECTORY;
    }

    public ErrorMap getErrorMap() {
        if (errorMap == null) {
            errorMap = new ADErrorMap();
        }
        return errorMap;
    }
}
