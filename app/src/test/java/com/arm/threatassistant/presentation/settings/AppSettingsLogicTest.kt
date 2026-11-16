package com.arm.threatassistant.presentation.settings

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppSettingsLogicTest {

    @Test
    fun languageDefaultsToSystemForUnknownOrMissingValues() {
        assertEquals(AppLanguage.SYSTEM, AppLanguage.fromStorageValue(null))
        assertEquals(AppLanguage.SYSTEM, AppLanguage.fromStorageValue(""))
        assertEquals(AppLanguage.SYSTEM, AppLanguage.fromStorageValue("FRENCH"))
    }

    @Test
    fun languageStorageRoundTrips() {
        AppLanguage.entries.forEach { language ->
            assertEquals(language, AppLanguage.fromStorageValue(language.name))
        }
    }

    @Test
    fun languageTagsMatchAndroidLocaleTags() {
        assertEquals("", AppLanguage.SYSTEM.languageTag)
        assertEquals("en", AppLanguage.ENGLISH.languageTag)
        assertEquals("hi", AppLanguage.HINDI.languageTag)
        assertEquals("ta", AppLanguage.TAMIL.languageTag)
    }

    @Test
    fun themeDefaultsToSystemForUnknownOrMissingValues() {
        assertEquals(AppTheme.SYSTEM, AppTheme.fromStorageValue(null))
        assertEquals(AppTheme.SYSTEM, AppTheme.fromStorageValue(""))
        assertEquals(AppTheme.SYSTEM, AppTheme.fromStorageValue("sepia"))
    }

    @Test
    fun themeStorageRoundTrips() {
        AppTheme.entries.forEach { theme ->
            assertEquals(theme, AppTheme.fromStorageValue(theme.storageValue))
        }
    }

    @Test
    fun darkThemeResolutionFollowsTheChoice() {
        assertTrue(resolveDarkTheme(AppTheme.DARK, systemInDarkTheme = false))
        assertFalse(resolveDarkTheme(AppTheme.LIGHT, systemInDarkTheme = true))
        assertTrue(resolveDarkTheme(AppTheme.SYSTEM, systemInDarkTheme = true))
        assertFalse(resolveDarkTheme(AppTheme.SYSTEM, systemInDarkTheme = false))
    }

    @Test
    fun explanationLanguageUsesExplicitChoice() {
        assertEquals("English", AppLanguage.ENGLISH.explanationLanguageName("ta"))
        assertEquals("Hindi", AppLanguage.HINDI.explanationLanguageName("en"))
        assertEquals("Tamil", AppLanguage.TAMIL.explanationLanguageName("en"))
    }

    @Test
    fun explanationLanguageFollowsDeviceOnlyForSystemChoice() {
        assertEquals("Hindi", AppLanguage.SYSTEM.explanationLanguageName("hi"))
        assertEquals("Tamil", AppLanguage.SYSTEM.explanationLanguageName("ta"))
        assertEquals("English", AppLanguage.SYSTEM.explanationLanguageName("en"))
        assertEquals("English", AppLanguage.SYSTEM.explanationLanguageName("fr"))
        assertEquals("English", AppLanguage.SYSTEM.explanationLanguageName(null))
    }
}
