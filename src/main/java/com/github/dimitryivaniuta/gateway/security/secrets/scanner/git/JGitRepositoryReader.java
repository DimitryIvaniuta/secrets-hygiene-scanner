package com.github.dimitryivaniuta.gateway.security.secrets.scanner.git;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.diff.DiffFormatter;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;

/** Reads commit messages and diffs using JGit (no external git binary). */
public class JGitRepositoryReader {

  private final Path repoRoot;

  public JGitRepositoryReader(Path repoRoot) {
    this.repoRoot = repoRoot;
  }

  /** Reads unified diff lines between base..head. */
  public List<String> readUnifiedDiffLines(String baseRef, String headRef) {
    try (Repository repo = open(); Git git = new Git(repo)) {
      ObjectId base = repo.resolve(Objects.requireNonNull(baseRef));
      ObjectId head = repo.resolve(Objects.requireNonNull(headRef));

      var diffs = git.diff()
          .setOldTree(Utils.prepareTreeParser(repo, base))
          .setNewTree(Utils.prepareTreeParser(repo, head))
          .call();

      ByteArrayOutputStream out = new ByteArrayOutputStream();
      try (DiffFormatter formatter = new DiffFormatter(out)) {
        formatter.setRepository(repo);
        formatter.format(diffs);
      }

      return out.toString(StandardCharsets.UTF_8).lines().toList();
    } catch (Exception e) {
      throw new IllegalStateException("Failed to read git diff " + baseRef + ".." + headRef, e);
    }
  }

  /** Reads commit message lines for commits in base..head. */
  public List<String> readCommitMessageLines(String baseRef, String headRef) {
    try (Repository repo = open(); Git git = new Git(repo)) {
      ObjectId base = repo.resolve(Objects.requireNonNull(baseRef));
      ObjectId head = repo.resolve(Objects.requireNonNull(headRef));

      var logs = git.log().addRange(base, head).call();
      StringBuilder sb = new StringBuilder();
      for (var c : logs) sb.append(c.getFullMessage()).append("
");
      return sb.toString().lines().toList();
    } catch (Exception e) {
      throw new IllegalStateException("Failed to read git log " + baseRef + ".." + headRef, e);
    }
  }

  private Repository open() throws IOException {
    return new FileRepositoryBuilder()
        .setWorkTree(repoRoot.toFile())
        .readEnvironment()
        .findGitDir(repoRoot.toFile())
        .build();
  }

  static final class Utils {
    static org.eclipse.jgit.treewalk.AbstractTreeIterator prepareTreeParser(Repository repository, ObjectId objectId)
        throws IOException {
      try (var walk = new org.eclipse.jgit.revwalk.RevWalk(repository)) {
        var commit = walk.parseCommit(objectId);
        var tree = walk.parseTree(commit.getTree().getId());
        var reader = repository.newObjectReader();
        var parser = new org.eclipse.jgit.treewalk.CanonicalTreeParser();
        parser.reset(reader, tree.getId());
        return parser;
      }
    }
  }
}
